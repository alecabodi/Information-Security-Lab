package katzwang.reductions;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;

import ddh.DDH_Challenge;
import ddh.I_DDH_Challenger;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFNMA_Adversary;
import katzwang.KatzWangPK;
import katzwang.KatzWangSignature;
import katzwang.KatzWangSolution;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

public class KatzWang_EUFNMA_Reduction extends A_KatzWang_EUFNMA_Reduction {
    DDH_Challenge<IGroupElement> challenge;
    HashMap<Triple<IGroupElement, IGroupElement, String>, BigInteger> table = new HashMap<>();

    public KatzWang_EUFNMA_Reduction(A_KatzWang_EUFNMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {

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

        return new KatzWangPK<>(challenge.generator, challenge.y, challenge.x, challenge.z);
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

}
