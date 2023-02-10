package cdh_quadratic;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import cdh.CDH_Challenge;
import cdh.I_CDH_Challenger;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

/**
 * This is the file you need to implement.
 *
 * Implement the methods {@code run} and {@code getChallenge} of this class.
 * Do not change the constructor of this class.
 */
public class CDH_Quad_Reduction extends A_CDH_Quad_Reduction<IGroupElement> {

    private IGroupElement g;
    private IGroupElement x;
    private IGroupElement y;
    private BigInteger p;

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public CDH_Quad_Reduction() {
        // Do not add any code here!
    }

    @Override
    public IGroupElement run(I_CDH_Challenger<IGroupElement> challenger) {

        CDH_Challenge<IGroupElement> challenge = challenger.getChallenge();
        this.g = challenge.generator;
        this.x = challenge.x;
        this.y = challenge.y;
        this.p = g.getGroupOrder();

        //take g^(axy)
        IGroupElement gAXY = f4(g, x, y);

        //compute g^(a^(p-3)) == g^(1/a^2) by fast exponentiation (skip first index since we start from g)
        IGroupElement tmp = g;
        IGroupElement gA2_inv = g;
        for (int i = 1; i < p.subtract(BigInteger.valueOf(3)).bitLength(); i++) {
            tmp = f4(g, tmp, tmp);

            if (p.subtract(BigInteger.valueOf(3)).testBit(i))
                gA2_inv = f4(g, gA2_inv, tmp);

        }

        // g^(a * axy * 1/a^2) = g^xy
        return f4(g, gAXY, gA2_inv);
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {

        // This is the second method you need to implement.
        // You need to create a CDH challenge here which will be given to your CDH
        // adversary.
        IGroupElement generator = this.g;
        IGroupElement x = this.x;
        IGroupElement y = this.y;
        // Instead of null, your cdh challenge should consist of meaningful group
        // elements.
        CDH_Challenge<IGroupElement> cdh_challenge = new CDH_Challenge<IGroupElement>(generator, x, y);

        return cdh_challenge;
    }

    IGroupElement f1(IGroupElement g, IGroupElement gX, IGroupElement gY) {

        return adversary.run(() -> new CDH_Challenge<>(g, gX, gY));
    }

    IGroupElement f2(IGroupElement g, IGroupElement gX, IGroupElement gY) {

        return f1(g, gX, gY).multiply(f1(g, g.power(BigInteger.ZERO), g.power(BigInteger.ZERO)).invert());
    }

    IGroupElement f3(IGroupElement g, IGroupElement gX, IGroupElement gY) {

        return f2(g, gX, gY).multiply(f2(g, g.power(BigInteger.ZERO), gY).invert());
    }

    IGroupElement f4(IGroupElement g, IGroupElement gX, IGroupElement gY) {

        return f3(g, gX, gY).multiply(f3(g, gX, g.power(BigInteger.ZERO)).invert());
    }

}
