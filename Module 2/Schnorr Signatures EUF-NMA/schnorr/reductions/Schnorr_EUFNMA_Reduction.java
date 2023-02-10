package schnorr.reductions;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFNMA_Adversary;
import schnorr.SchnorrSolution;
import schnorr.Schnorr_PK;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

public class Schnorr_EUFNMA_Reduction extends A_Schnorr_EUFNMA_Reduction {
    I_DLog_Challenger<IGroupElement> challenger;
    Map<Pair<String, IGroupElement>, BigInteger> table = new HashMap<>();

    public Schnorr_EUFNMA_Reduction(I_Schnorr_EUFNMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        DLog_Challenge<IGroupElement> challenge = challenger.getChallenge();
        IGroupElement g = challenge.generator;
        IGroupElement x = challenge.x;

        return new Schnorr_PK<>(g, x);
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {

        Pair<String, IGroupElement> pair = new Pair<>(message, r);

        //consistency
        if (table.containsKey(pair))
            return table.get(pair);

        BigInteger random = NumberUtils.getRandomBigInteger(new Random(),
                challenger.getChallenge().generator.getGroupOrder());

        table.put(pair, random);

        return random;
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {

        this.challenger = challenger;

        long seed = 42L; //random seed
        adversary.reset(seed);

        SchnorrSolution<BigInteger> sig0 = adversary.run(this);

        adversary.reset(seed);
        table.clear();

        SchnorrSolution<BigInteger> sig1 = adversary.run(this);

        BigInteger x = sig0.signature.s.subtract(sig1.signature.s).multiply(sig0.signature.c.subtract(sig1.signature.c).modInverse(challenger.getChallenge().generator.getGroupOrder()));

        return x;

    }

}
