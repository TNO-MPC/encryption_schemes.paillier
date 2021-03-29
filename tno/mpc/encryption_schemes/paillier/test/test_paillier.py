from time import time

import pytest
from typing import cast
from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.encryption_schemes.utils import mod_inv


paillier_scheme: Paillier = Paillier.from_security_parameter(
    key_length=1024, nr_of_threads=3, debug=False
)
paillier_scheme_floats: Paillier = Paillier.from_security_parameter(
    key_length=1024, precision=10, nr_of_threads=3, debug=False
)

test_vals_integers = list(range(-20, 20))
test_vals_integer_pairs = [(i, i + 1) for i in range(-20, 20)] + [
    (-i, i + 1) for i in range(20)
]
test_vals_float_pairs = [
    (round(i * 10 ** -3, 3), round((i + 1) * 10 ** -2, 2)) for i in range(-20, 20)
] + [(round(-i * 10 ** -3, 3), round((i + 1) * 10 ** -2, 2)) for i in range(20)]
test_vals_float_int_pairs = [
    (round(i * 10 ** -3, 3), i + 1) for i in range(-20, 20)
] + [(round(-i * 10 ** -3, 3), i + 1) for i in range(20)]


def test_setup():
    """
    Test the correctness of the Paillier initializer.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    mu = paillier_scheme.secret_key.mu
    g = paillier_scheme.public_key.g
    n = paillier_scheme.public_key.n
    n_squared = paillier_scheme.public_key.n_squared
    lambda_ = paillier_scheme.secret_key.lambda_
    mu_prime = mod_inv(paillier_scheme.func_l(pow(g, lambda_, n_squared), n), n)
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert mu == mu_prime


def test_different_inits():
    """
    Test different initializer of the Paillier scheme.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    public_key = paillier_scheme.public_key
    secret_key = paillier_scheme.secret_key
    same_scheme = Paillier(public_key, secret_key)
    same_scheme.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert paillier_scheme == same_scheme


@pytest.mark.parametrize("value", test_vals_integers)
def test_encryption(value):
    """
    Test encryption/decryption in the Paillier scheme.
    :param value: Plaintext
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    encrypted_value = paillier_scheme.encrypt(value)
    decrypted_value = paillier_scheme.decrypt(encrypted_value)
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert value == decrypted_value


@pytest.mark.parametrize("value", test_vals_integers)
def test_encryption_with_rerandomization(value):
    """
    Test encryption/decryption in the Paillier scheme with rerandomization of the ciphertext.
    :param value: Plaintext
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    encrypted_value: PaillierCiphertext = cast(
        PaillierCiphertext, paillier_scheme.encrypt(value)
    )
    decrypted_value = paillier_scheme.decrypt(encrypted_value)
    encrypted_value_prime = encrypted_value.copy()
    encrypted_value_prime.randomize()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert encrypted_value != encrypted_value_prime
    assert value == decrypted_value


@pytest.mark.parametrize("value1, value2", test_vals_integer_pairs)
def test_homomorphic_addition(value1, value2):
    """
    Test homomorphic addition of two encrypted values.
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    encrypted_value1 = paillier_scheme.encrypt(value1)
    encrypted_value2 = paillier_scheme.encrypt(value2)
    encrypted_sum_both_enc = encrypted_value1 + encrypted_value2
    encrypted_sum_plain1 = value1 + encrypted_value2
    decrypted_sum_both_enc = paillier_scheme.decrypt(encrypted_sum_both_enc)
    decrypted_sum_plain1 = paillier_scheme.decrypt(encrypted_sum_plain1)
    correct_sum = value1 + value2
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert decrypted_sum_both_enc == decrypted_sum_plain1 == correct_sum


@pytest.mark.parametrize("value1, value2", test_vals_float_pairs)
def test_homomorphic_addition_floats(value1, value2):
    """
    Test homomorphic addition of two encrypted values that are floats.
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    encrypted_value1 = paillier_scheme_floats.encrypt(value1)
    encrypted_value2 = paillier_scheme_floats.encrypt(value2)
    encrypted_sum = encrypted_value1 + encrypted_value2
    decrypted_sum = paillier_scheme_floats.decrypt(encrypted_sum)
    correct_sum = round(value1 + value2, paillier_scheme_floats.precision)
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert decrypted_sum == correct_sum


def homomorphic_subtraction(value1, value2, floats=False):
    """
    Test homomorphic subtraction of two encrypted values, both __sub__ and __rsub__.
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    correct_diff = value1 - value2
    scheme = paillier_scheme_floats if floats else paillier_scheme
    encrypted_value1 = scheme.encrypt(value1)
    encrypted_value2 = scheme.encrypt(value2)

    encrypted_diff_both_enc = encrypted_value1 - encrypted_value2
    decrypted_diff_both_enc = scheme.decrypt(encrypted_diff_both_enc)

    encrypted_diff_with_plain1 = value1 - encrypted_value2
    decrypted_diff_with_plain1 = scheme.decrypt(encrypted_diff_with_plain1)

    encrypted_diff_with_plain2 = encrypted_value1 - value2
    decrypted_diff_with_plain2 = scheme.decrypt(encrypted_diff_with_plain2)

    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()

    assert abs(decrypted_diff_both_enc - correct_diff) < 0.00001
    assert abs(decrypted_diff_with_plain1 - correct_diff) < 0.00001
    assert abs(decrypted_diff_with_plain2 - correct_diff) < 0.00001


@pytest.mark.parametrize("value1, value2", test_vals_integer_pairs)
def test_homomorphic_subtraction_ints(value1, value2):
    """
    Test homomorphic subtraction of two encrypted values, both __sub__ and __rsub__.
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    homomorphic_subtraction(value1, value2, False)


@pytest.mark.parametrize("value1, value2", test_vals_float_pairs)
def test_homomorphic_subtraction_floats(value1, value2):
    """
    Test homomorphic subtraction of two encrypted values, both __sub__ and __rsub__.
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    homomorphic_subtraction(value1, value2, True)


@pytest.mark.parametrize("value1, value2", test_vals_integer_pairs)
def test_homomorphic_multiplication(value1, value2):
    """
    Test homomorphic multiplication of two encrypted values. (The scheme should throw an error.)
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    encrypted_value1 = paillier_scheme.encrypt(value1)
    encrypted_value2 = paillier_scheme.encrypt(value2)
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    with pytest.raises(TypeError):
        _encrypted_sum = encrypted_value1 * encrypted_value2


@pytest.mark.parametrize("value1, value2", test_vals_float_pairs)
def test_homomorphic_scalar_multiplication_floats(value1, value2):
    """
    Test the multiplication of an encrypted  value with a plaintext value.
    This should throw an error, as the scheme does not support float scalars
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    encrypted_value1 = paillier_scheme_floats.encrypt(value1)
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    with pytest.raises(TypeError):
        _ = encrypted_value1 * value2


def homomorphic_scalar_multiplication(value1, value2, floats=False):
    """
    Test the multiplication of an encrypted integer value with a plaintext integer value.
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    scheme = paillier_scheme_floats if floats else paillier_scheme
    encrypted_value1 = scheme.encrypt(value1)
    encrypted_prod_1 = encrypted_value1 * value2
    encrypted_prod_2 = value2 * encrypted_value1
    decrypted_prod_1 = scheme.decrypt(encrypted_prod_1)
    decrypted_prod_2 = scheme.decrypt(encrypted_prod_2)
    correct_prod = value1 * value2
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert abs(correct_prod - decrypted_prod_1) < 0.0001
    assert abs(correct_prod - decrypted_prod_2) < 0.0001


@pytest.mark.parametrize("value1, value2", test_vals_integer_pairs)
def test_homorphic_scalar_multiplication_ints(value1, value2):
    """
    Test the multiplication of an encrypted float value with a plaintext float value.
    This should throw an error, as the scheme does not support float scalars
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    homomorphic_scalar_multiplication(value1, value2, False)


@pytest.mark.parametrize("value1, value2", test_vals_float_int_pairs)
def test_homorphic_scalar_multiplication_ints(value1, value2):
    """
    Test the multiplication of an encrypted integer value with a plaintext float value.
    This should throw an error, as the scheme does not support float scalars
    :param value1: First plaintext value.
    :param value2: Second plaintext value.
    """
    homomorphic_scalar_multiplication(value1, value2, True)


def _test_time():
    """
    Determine the runtime of one encryption.
    """
    start_time = time()
    for i in range(50):
        paillier_scheme.encrypt(i)
    test_time = time() - start_time
    print(test_time / 100)
    assert True
