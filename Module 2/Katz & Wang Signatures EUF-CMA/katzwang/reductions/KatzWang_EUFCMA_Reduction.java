package katzwang.reductions;

import java.math.BigInteger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import ddh.DDH_Challenge;
import ddh.I_DDH_Challenger;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFCMA_Adversary;
import katzwang.KatzWangPK;
import katzwang.KatzWangSignature;
import katzwang.KatzWangSolution;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

public class KatzWang_EUFCMA_Reduction extends A_KatzWang_EUFCMA_Reduction {
    DDH_Challenge<IGroupElement> challenge;
    HashMap<Triple<IGroupElement, IGroupElement, String>, BigInteger> table = new HashMap<>();
    KatzWangPK<IGroupElement> pk;

    public KatzWang_EUFCMA_Reduction(A_KatzWang_EUFCMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {
        // Implement your code here!

        this.challenge = challenger.getChallenge();
        KatzWangSolution<BigInteger> sol;

        if ((sol = adversary.run(this)) == null)
            return false;

        IGroupElement A = challenge.generator.power(sol.signature.s).
                multiply(challenge.x.power(sol.signature.c.negate()));
        IGroupElement B = challenge.y.power(sol.signature.s).
                multiply(challenge.z.power(sol.signature.c.negate()));;

        return hash(A, B, sol.message).equals(sol.signature.c);
    }

    @Override
    public KatzWangPK<IGroupElement> getChallenge() {
        this.pk = new KatzWangPK<>(challenge.generator, challenge.y, challenge.x, challenge.z);

        return pk;
    }

    @Override
    public BigInteger hash(IGroupElement comm1, IGroupElement comm2, String message) {
        Triple<IGroupElement, IGroupElement, String> triple = new Triple<>(comm1, comm2, message);

        //consistency
        if (table.containsKey(triple))
            return table.get(triple);

        BigInteger randomNumber = NumberUtils.getRandomBigInteger(new Random(), challenge.generator.getGroupOrder());

        table.put(triple, randomNumber);

        return randomNumber;
    }

    @Override
    public KatzWangSignature<BigInteger> sign(String message) {

        BigInteger k = NumberUtils.getRandomBigInteger(new Random(),
                challenge.generator.getGroupOrder());

        BigInteger random = NumberUtils.getRandomBigInteger(new Random(),
                challenge.generator.getGroupOrder());

        IGroupElement A = pk.g.power(k).multiply(pk.y_1.power(random.negate()));
        IGroupElement B = pk.h.power(k).multiply(pk.y_2.power(random.negate()));

        Triple<IGroupElement, IGroupElement, String> triple = new Triple<>(A, B, message);

        table.put(triple, random);

        return new KatzWangSignature<>(random, k);
    }
}
