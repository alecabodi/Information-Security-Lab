package rsapkcs;

import schemes.RSAPKCS_OWCL_Challenger;

import java.math.BigInteger;
import java.math.*;
import java.util.*;
import java.util.function.BiFunction;

import static utils.NumberUtils.getRandomBigInteger;
import static utils.NumberUtils.ceilDivide;
import static utils.NumberUtils.getCeilLog;

public class RSAPKCS_OWCL_Adversary implements I_RSAPKCS_OWCL_Adversary {
    public RSAPKCS_OWCL_Adversary() {
        // Do not change this constructor!
    }

    /*
     * @see basics.IAdversary#run(basics.IChallenger)
     */
    @Override
    public BigInteger run(final I_RSAPKCS_OWCL_Challenger challenger) {
        // solution from paper of the attack is implemented
        BigInteger m_prime_padded = BigInteger.ZERO;

            /*
            * vulnerability: padding put constraints on the value of m_pad s.t. A < m_pad < B
            * => we can exploit homomorphic encryption to try and progressively reduce interval until we get single element m
            */
            try {
                //we can assume first ciphertext is from correctly padded message (from Moodle discussion)
                m_prime_padded = attack(challenger);
            } catch (Exception e) {
                System.out.println("Exception");
            }


        return unpad(m_prime_padded, challenger);
    }

    private BigInteger unpad(BigInteger m_prime_padded, I_RSAPKCS_OWCL_Challenger challenger) {

        byte[] bytearray = m_prime_padded.toByteArray();
        byte[] new_bytearray = new byte[challenger.getPlainTextLength()+1];

        int j = 0;
        for (int i = bytearray.length-new_bytearray.length; i  < bytearray.length; i++) {
            new_bytearray[j++] = bytearray[i];
        }

        return new BigInteger(new_bytearray);
    }

    private BigInteger attack(I_RSAPKCS_OWCL_Challenger challenger) throws Exception {
        RSAPKCS_PK pk = challenger.getPk();

        int k = (int)Math.ceil((double)pk.N.bitLength() / 8.0);

        BigInteger bound = BigInteger.TWO.pow(8*(k-2));

        //lower bound a = 00||02||00...0||00||00
        BigInteger A = bound.multiply(BigInteger.TWO);

        //upper bound B = 00||02||11...1||00||11 => for simplicity just take B = 00||02||11...1||11||11 = 3 * bound - 1
        BigInteger B = bound.multiply(BigInteger.valueOf(3)).subtract(BigInteger.ONE);

        //initiate coefficient for homomorphic encryption
        //values lower than this make no sense => PKCS compliance not possible (subtract one since computeS immediately adds 1)
        Coefficient s = new Coefficient(ceilDivide(pk.N, BigInteger.valueOf(3).multiply(bound)).subtract(BigInteger.ONE));

        //use sets instead of arrays to avoid duplicate intervals => simpler code
        Set<Interval> new_intervals = new HashSet<>();
        Set<Interval> intervals = new HashSet<>();
        intervals.add(new Interval(A,B));
        BigInteger a;
        BigInteger b;
        BigInteger new_a;
        BigInteger new_b;

        while (true) {

            //if interval is actually a single value then that's our message
            if (intervals.size() == 1) {
                Interval i = intervals.stream().findFirst().get();
                if (i.getL().equals(i.getH()))
                    return i.getL();
            }

            //compute coefficient to exploit homomorphic encryption
            s.computeS(challenger, intervals, A, B);

            //iterate over the intervals
            for (Interval i : intervals) {

                //try to reduce interval => implement formulas

                BigInteger N1 = ceilDivide(s.getS().multiply(i.getL()).subtract(B), pk.N);
                BigInteger N2 = ceilDivide(s.getS().multiply(i.getH()).subtract(A), pk.N);

                for (BigInteger n = N1; n.compareTo(N2) < 0; n = n.add(BigInteger.ONE)) {

                    a = ceilDivide(A.add(n.multiply(pk.N)), s.getS());
                    // for b we need to floor => use ceil then subtract 1
                    b = ceilDivide(B.add(n.multiply(pk.N)), s.getS()).subtract(BigInteger.ONE);

                    //intersection
                    if (i.getL().compareTo(a) < 0)
                        new_a = a;
                    else
                        new_a = i.getL();

                    if (b.compareTo(i.getH()) < 0)
                        new_b = b;
                    else
                        new_b = i.getH();

                    //check it is an interval
                    if (new_a.compareTo(new_b) <= 0)
                        new_intervals.add(new Interval(new_a, new_b));

                }

            }

            //progressively reduce the intervals of search
            intervals = Set.copyOf(new_intervals);
            //reset
            new_intervals.clear();

        }
        
        


    }

    private static class Coefficient {

        private BigInteger s;
        private boolean first_request;

        public Coefficient(BigInteger s) {
            this.s = s;
            this.first_request = true;
        }

        public BigInteger getS() {
            return s;
        }

        public void computeS(I_RSAPKCS_OWCL_Challenger challenger, Collection<Interval> intervals, BigInteger A, BigInteger B)
                throws Exception {

            BigInteger c = challenger.getChallenge();
            RSAPKCS_PK pk = challenger.getPk();

            // query challenger until we get PKCS conforming s*m, such that we can continue to work on reducing interval
            if (!first_request && intervals.size() == 1) {

                Interval i = intervals.stream().findFirst().get();
                BigInteger r = ceilDivide(BigInteger.TWO.multiply(i.getH().multiply(s).subtract(A)), pk.N);

                while (true) { //until we find right s

                    BigInteger S1 = ceilDivide(A.add(r.multiply(pk.N)), i.getH());
                    BigInteger S2 = ceilDivide(B.add(r.multiply(pk.N)), i.getL());
                    // find s in range until we found one for which s^e*c is PKCS conforming,
                    // => we can exploit bounds from padding
                    for (s = S1; s.compareTo(S2) < 0; s = s.add(BigInteger.ONE)) {
                        BigInteger new_c = s.modPow(pk.exponent, pk.N).multiply(c).mod(pk.N);
                        if (challenger.isPKCSConforming(new_c))
                            return;

                    }

                    r = r.add(BigInteger.ONE);

                }

            } else {

                if (first_request)
                    first_request = false;

                while(true) {
                    // progressively increment s until we found one for which s^e*c is PKCS conforming,
                    // => we can exploit bounds from padding
                    s = s.add(BigInteger.ONE);
                    BigInteger new_c = s.modPow(pk.exponent, pk.N).multiply(c).mod(pk.N);
                    if (challenger.isPKCSConforming(new_c))
                        return;

                }

            }

        }
        
    }

    private static class Interval {
        private BigInteger l;
        private BigInteger h;

        public Interval(BigInteger l, BigInteger h) {
            this.l = l;
            this.h = h;
        }

        public BigInteger getL() {
            return l;
        }

        public void setL(BigInteger l) {
            this.l = l;
        }

        public BigInteger getH() {
            return h;
        }

        public void setH(BigInteger h) {
            this.h = h;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Interval interval = (Interval) o;
            return l.equals(interval.l) && h.equals(interval.h);
        }

        @Override
        public int hashCode() {
            return Objects.hash(l, h);
        }
    }
        

}