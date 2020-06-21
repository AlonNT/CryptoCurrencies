import numpy as np

MAX_STATES = 30   # The maximal number of states in the Markov chain.
alpha = 0.25      # The amount of compute power the attacker has.

# The maximal allowed difference between the current power of the
# transition matrix and the previous power, as well as the maximal
# allowed difference between any two rows in the final transition
# matrix (i.e. each row approaches the stationary distribution).
epsilon = 0.0001

# We create the transition-matrix of the Markov chain.
# The entry i,j is the probability of the transition from state i to j.
# It's a stochastic matrix, meaning that its entries are non-negative,
# and each row sums to 1 (indeed, for every i the sum over j of the
# probabilities of the transition from i to j is 1).
P = np.zeros(shape=(MAX_STATES, MAX_STATES), dtype=np.float32)
for i in range(MAX_STATES):
    P[i, max(0, i - 1)] = 1 - alpha
    P[i, min(MAX_STATES - 1, i + 1)] = alpha

# Now we raise the matrix P to powers 2^i for i = 1,2,...
# Until we are close to the stationary distribution.
previous_power_matrix = np.eye(len(P))
power_matrix = P
stationary_found = False
while not stationary_found:
    previous_power_matrix = power_matrix
    power_matrix = np.dot(previous_power_matrix, previous_power_matrix)

    # Check if the two matrices P^{2^i} and P^{2^{i-1}} are the same
    # (up to epsilon).
    matrices_are_close = (
            np.linalg.norm(power_matrix - previous_power_matrix,
                           ord=np.inf) < epsilon
    )

    # (P[i] - P) gets the diff between the i-th row and all other rows.
    # np.delete removes the i-th row from this matrix (since it's zero).
    # np.linalg.norm gets the norm of every row in this diff-matrix.
    # np.amax gets the max distance between the i-th row and another row.
    # Finally, loop over i to find the max distance between any two rows.
    max_diff_between_rows = max(
        np.amax(np.linalg.norm(np.delete(power_matrix[i] - power_matrix, i,
                                         axis=0),
                               axis=0, ord=np.inf))
        for i in range(MAX_STATES)
    )

    # Check that the rows of the matrix are all the same (up to epsilon).
    # Each row approaches the stationary distribution,
    # when the power approaches infinity.
    rows_are_close = (max_diff_between_rows < epsilon)

    # We stop when both the diff between P^{2^{i-1}} and P^{2^i} is small,
    # and the difference between the rows in P^{2^i} is small.
    stationary_found = matrices_are_close and rows_are_close

empirical_stationary_distribution = power_matrix[0]
print(empirical_stationary_distribution)

# Now calculate the theoretical stationary distribution
# and print the maximal difference between it and the empirical.
q = alpha / (1 - alpha)
theoretical_stationary_distribution = ((1 - q) *
                                       np.power(q, np.arange(MAX_STATES)))
print('Maximal diff between empirical and theoretical is {}'.format(
    np.linalg.norm(empirical_stationary_distribution -
                   theoretical_stationary_distribution, ord=np.inf)
))
