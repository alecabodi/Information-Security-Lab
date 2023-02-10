package ddh;

import basics.IChallenger;

/**
 * A DDH challenger provides DDH challenges and plays the security game of the
 * DDH assumption with implementations of the {@code I_DDH_Adversary} interface.
 * It has a method {@code getChallenge()} which will be called by a DDH
 * adversary and which provides the DDH challenge in the corresponding security
 * game.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 */
public interface I_DDH_Challenger<G, E> extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    DDH_Challenge<G> getChallenge();
}
