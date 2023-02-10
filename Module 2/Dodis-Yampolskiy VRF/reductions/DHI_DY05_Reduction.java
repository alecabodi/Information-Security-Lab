package reductions;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import algebra.SimplePolynomial;
import dhi.DHI_Challenge;
import dhi.I_DHI_Challenger;
import dy05.DY05_PK;
import dy05.I_Selective_DY05_Adversary;
import genericGroups.IGroupElement;

public class DHI_DY05_Reduction implements I_DHI_DY05_Reduction {
    // Do not remove this field!
    private final I_Selective_DY05_Adversary adversary;
    private BigInteger x0;
    private BigInteger p;
    private BigInteger q;
    private SimplePolynomial f;
    private IGroupElement g;
    private List<IGroupElement> gAlpha;
    private List<IGroupElement> gBeta;

    public DHI_DY05_Reduction(I_Selective_DY05_Adversary adversary) {
        // Do not change this constructor!
        this.adversary = adversary;
    }

    @Override
    public IGroupElement run(I_DHI_Challenger challenger) {

        DHI_Challenge challenge = challenger.getChallenge();

        //store gAlpha
        this.gAlpha = new ArrayList<>();
        for (BigInteger j = BigInteger.ZERO; j.compareTo(BigInteger.valueOf(challenge.size())) < 0; j = j.add(BigInteger.ONE))
            gAlpha.add(challenge.get(j.intValue()));

        this.g = gAlpha.get(0);
        this.q = BigInteger.valueOf(challenge.size() - 1);
        this.p = g.getGroupOrder();

        //output forgery sigma_star
        IGroupElement sigma_star = adversary.run(this);
        if (sigma_star == null)
            return null;

        //eval gamma_min1 exploiting absence of remainder in division: divide and multiply by factor (z + x0), the difference between f and f_prime is gamma_min1 (from lab session hint)
        SimplePolynomial z_plus_x0 = new SimplePolynomial(p, x0, BigInteger.ONE);
        SimplePolynomial f_prime = f.div(z_plus_x0);
        BigInteger gamma_min1 = f.subtract(f_prime.multiply(z_plus_x0)).get(0);

        //eval gAlpha_inv implementing paper formula
        IGroupElement gAlpha_inv = sigma_star;

        for (BigInteger j = BigInteger.ZERO; j.compareTo(q.subtract(BigInteger.TWO)) <= 0; j = j.add(BigInteger.ONE))
            gAlpha_inv = gAlpha_inv.multiply(gBeta.get(j.intValue()).power(f_prime.get(j.intValue()).negate()));

        gAlpha_inv = gAlpha_inv.power(gamma_min1.modInverse(p));

        return gAlpha_inv;
    }

    @Override
    public void receiveChallengePreimage(int _challenge_preimage) throws Exception {
        this.x0 = BigInteger.valueOf(_challenge_preimage);
    }

    @Override
    public IGroupElement eval(int preimage) {
        BigInteger xi = BigInteger.valueOf(preimage);
        //from paper, when responding to oracle queries fail if xi == x0
        if (xi.equals(x0))
            return null;

        //otherwise return y_i
        SimplePolynomial z_plus_xi = new SimplePolynomial(p, xi, BigInteger.ONE);
        SimplePolynomial f_i = f.div(z_plus_xi);

        IGroupElement y_i = g.power(BigInteger.ZERO);
        for(BigInteger j = BigInteger.ZERO; j.compareTo(q.subtract(BigInteger.TWO)) <= 0; j = j.add(BigInteger.ONE))
            y_i = y_i.multiply(gBeta.get(j.intValue()).power(f_i.get(j.intValue())));

        return y_i;
    }

    @Override
    public DY05_PK getPK() {
        //eval f(z)
        this.f = new SimplePolynomial(p, BigInteger.ONE);

        for (BigInteger w = BigInteger.ZERO; w.compareTo(q) < 0; w = w.add(BigInteger.ONE)){
            if (!w.equals(x0))
                f = f.multiply(new SimplePolynomial(p, w, BigInteger.ONE));
        }

        //eval gBeta with binomial theorem: use SimplePolynomial for simplicity
        this.gBeta = new ArrayList<>();

        //add first element in gBeta i.e. g
        gBeta.add(g.power(BigInteger.ONE));

        SimplePolynomial alpha_min_x0 = new SimplePolynomial(p, x0.negate(), BigInteger.ONE);
        SimplePolynomial binomial_expansion = new SimplePolynomial(p, BigInteger.ONE);
        IGroupElement gBeta_tmp = g.power(BigInteger.ZERO);

        for (BigInteger j = BigInteger.ONE; j.compareTo(q) <= 0; j = j.add(BigInteger.ONE)){
            binomial_expansion = binomial_expansion.multiply(alpha_min_x0);

            for (BigInteger i = BigInteger.ZERO; i.compareTo(j) <= 0; i = i.add(BigInteger.ONE))
                gBeta_tmp = gAlpha.get(i.intValue()).power(binomial_expansion.get(i.intValue())).multiply(gBeta_tmp);

            gBeta.add(gBeta_tmp);
            gBeta_tmp = g.power(BigInteger.ZERO); //reset
        }

        //eval h = generator for pk
        IGroupElement h = g.power(BigInteger.ZERO);
        for (BigInteger j = BigInteger.ZERO; j.compareTo(q) < 0; j = j.add(BigInteger.ONE))
             h = h.multiply(gBeta.get(j.intValue()).power(f.get(j.intValue())));

        //eval hBeta = gS for pk
        IGroupElement hBeta = g.power(BigInteger.ZERO);
        for (BigInteger j = BigInteger.ONE; j.compareTo(q) <= 0; j = j.add(BigInteger.ONE))
            hBeta = hBeta.multiply(gBeta.get(j.intValue()).power(f.get(j.intValue()-1)));

        return new DY05_PK(h, hBeta);
    }

}
