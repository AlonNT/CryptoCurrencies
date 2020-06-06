import numpy as np
import matplotlib.pyplot as plt
from tqdm import tqdm

# Approximation guarantee (in order to "sum an infinite sum",
# we require the last element to be less than EPSILON.
EPSILON = 1e-49

# The infinite sum will be summed up to MAX_N,
# guaranteed that its last elements will be less than EPSILON.
MAX_N = 10 ** 6

# The maximal i to check its result.
MAX_I = 10000

k = 10 ** 4  # A share will be valid if it's at most k multiplied by the target.
r = np.arange(MAX_N)  # Will be used for the summation.
mutual_arr = ((1 - (1 / k)) ** r)  # Will be used for the summation.

results = np.empty(MAX_I)

for j in tqdm(range(1, MAX_I+1)):
    arr = (1 / (r + j)) * mutual_arr
    assert arr[-1] < EPSILON, "The approximation is not good enough"
    results[j-1] = np.sum(arr)

i = np.where(results < 1)[0][0]
plt.scatter(i, results[i])
plt.axhline(y=1, color='gray', linestyle='--')
plt.axvline(x=i, color='gray', linestyle='--')
plt.ylim(0, 3)
plt.plot(results)
plt.savefig('q3.svg')
plt.show()

print(f"For i={i} the result is {results[i]:.5f}, "
      f"whereas for i={i-1} the result is {results[i-1]:.5f}")
