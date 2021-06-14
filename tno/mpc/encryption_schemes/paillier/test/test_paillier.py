"""
This module tests the construction and use of Paillier instances.
"""

from time import time
from typing import Union

import pytest
from tno.mpc.encryption_schemes.utils import mod_inv
from tno.mpc.encryption_schemes.utils.fixed_point import FixedPoint

from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.encryption_schemes.paillier.test import paillier_scheme

test_values_integers = list(range(-20, 20))
test_values_floats = [float(_) / 40 for _ in range(-20, 20)]
test_values_integer_pairs = [(i, i + 1) for i in range(-20, 20)] + [
    (-i, i + 1) for i in range(20)
]
test_values_float_pairs = [
    (round(i * 10 ** -3, 3), round((i + 1) * 10 ** -2, 2)) for i in range(-20, 20)
] + [(round(-i * 10 ** -3, 3), round((i + 1) * 10 ** -2, 2)) for i in range(20)]
test_values_float_int_pairs = [
    (round(i * 10 ** -3, 3), i + 1) for i in range(-20, 20)
] + [(round(-i * 10 ** -3, 3), i + 1) for i in range(20)]


@pytest.mark.parametrize("with_precision", (True, False))
def test_setup(with_precision: bool) -> None:
    """
    Test the correctness of the Paillier initializer.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.boot_generation()
    mu = scheme.secret_key.mu
    g = scheme.public_key.g
    n = scheme.public_key.n
    n_squared = scheme.public_key.n_squared
    lambda_ = scheme.secret_key.lambda_
    mu_prime = mod_inv(scheme.func_l(pow(g, lambda_, n_squared), n), n)
    scheme.shut_down()
    assert mu == mu_prime


@pytest.mark.parametrize("with_precision", (True, False))
def test_different_inits(with_precision: bool) -> None:
    """
    Test different initializer of the Paillier scheme.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.boot_generation()
    public_key = scheme.public_key
    secret_key = scheme.secret_key
    precision = scheme.precision
    same_scheme = Paillier(public_key, secret_key, precision=precision)
    same_scheme.shut_down()
    scheme.shut_down()
    assert scheme == same_scheme


@pytest.mark.parametrize(
    "value, with_precision",
    [(_, True) for _ in test_values_floats]
    + [(_, True) for _ in test_values_integers]
    + [(_, False) for _ in test_values_integers],
)
def test_encryption(value: Union[float, int], with_precision: bool) -> None:
    """
    Test encryption/decryption in the Paillier scheme.

    :param value: plaintext
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    fxp_value = FixedPoint.fxp(value)
    scheme.boot_generation()
    encrypted_value = scheme.encrypt(value)
    decrypted_value = scheme.decrypt(encrypted_value)
    scheme.shut_down()
    assert fxp_value == decrypted_value


@pytest.mark.parametrize(
    "value, with_precision",
    [(_, True) for _ in test_values_floats]
    + [(_, True) for _ in test_values_integers]
    + [(_, False) for _ in test_values_integers],
)
def test_encryption_with_rerandomization(
    value: Union[float, int], with_precision: bool
) -> None:
    """
    Test encryption/decryption in the Paillier scheme with rerandomization of the ciphertext.

    :param value: plaintext
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    fxp_value = FixedPoint.fxp(value)
    scheme.boot_generation()
    encrypted_value: PaillierCiphertext = scheme.encrypt(fxp_value)
    decrypted_value = scheme.decrypt(encrypted_value)
    encrypted_value_prime = encrypted_value.copy()
    encrypted_value_prime.randomize()
    scheme.shut_down()
    assert encrypted_value != encrypted_value_prime
    assert fxp_value == decrypted_value


@pytest.mark.parametrize(
    "value_1, value_2, with_precision",
    [_ + (True,) for _ in test_values_float_pairs]
    + [_ + (True,) for _ in test_values_integer_pairs]
    + [_ + (True,) for _ in test_values_float_int_pairs]
    + [_ + (False,) for _ in test_values_integer_pairs],
)
def test_homomorphic_addition(
    value_1: Union[float, int], value_2: Union[float, int], with_precision: bool
) -> None:
    """
    Test homomorphic addition of two encrypted values.

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.boot_generation()
    encrypted_value_1 = scheme.encrypt(value_1)
    encrypted_value_2 = scheme.encrypt(value_2)
    encrypted_sum_both_enc = encrypted_value_1 + encrypted_value_2
    encrypted_sum_plain1 = value_1 + encrypted_value_2
    decrypted_sum_both_enc = scheme.decrypt(encrypted_sum_both_enc)
    decrypted_sum_plain1 = scheme.decrypt(encrypted_sum_plain1)
    fxp_1 = FixedPoint.fxp(value_1, scheme.precision)
    fxp_2 = FixedPoint.fxp(value_2, scheme.precision)
    correct_sum = fxp_1 + fxp_2
    scheme.shut_down()
    assert decrypted_sum_both_enc == decrypted_sum_plain1 == correct_sum


@pytest.mark.parametrize(
    "value_1, value_2, with_precision",
    [_ + (True,) for _ in test_values_float_pairs]
    + [_ + (True,) for _ in test_values_integer_pairs]
    + [_ + (True,) for _ in test_values_float_int_pairs]
    + [_ + (False,) for _ in test_values_integer_pairs],
)
def test_homomorphic_subtraction(
    value_1: Union[float, int], value_2: Union[float, int], with_precision: bool
) -> None:
    """
    Test homomorphic subtraction of two encrypted values, both __sub__ and __rsub__.

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.boot_generation()

    fxp_1 = FixedPoint.fxp(value_1, scheme.precision)
    fxp_2 = FixedPoint.fxp(value_2, scheme.precision)
    encrypted_value_1 = scheme.encrypt(value_1)
    encrypted_value_2 = scheme.encrypt(value_2)
    correct_diff = fxp_1 - fxp_2

    encrypted_diff_both_enc = encrypted_value_1 - encrypted_value_2
    decrypted_diff_both_enc = scheme.decrypt(encrypted_diff_both_enc)

    encrypted_diff_with_plain1 = value_1 - encrypted_value_2
    decrypted_diff_with_plain1 = scheme.decrypt(encrypted_diff_with_plain1)

    encrypted_diff_with_plain2 = encrypted_value_1 - value_2
    decrypted_diff_with_plain2 = scheme.decrypt(encrypted_diff_with_plain2)

    scheme.shut_down()

    assert decrypted_diff_both_enc == correct_diff
    assert decrypted_diff_with_plain1 == correct_diff
    assert decrypted_diff_with_plain2 == correct_diff


@pytest.mark.parametrize(
    "value_1, value_2, with_precision",
    [_ + (True,) for _ in test_values_float_pairs]
    + [_ + (True,) for _ in test_values_integer_pairs]
    + [_ + (True,) for _ in test_values_float_int_pairs]
    + [_ + (False,) for _ in test_values_integer_pairs],
)
def test_homomorphic_multiplication(
    value_1: Union[float, int], value_2: Union[float, int], with_precision: bool
) -> None:
    """
    Test homomorphic multiplication of two encrypted values. (The scheme should throw an error)

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.boot_generation()
    encrypted_value_1 = scheme.encrypt(value_1)
    encrypted_value_2 = scheme.encrypt(value_2)
    scheme.shut_down()
    with pytest.raises(TypeError):
        _encrypted_sum = encrypted_value_1 * encrypted_value_2


@pytest.mark.parametrize(
    "value_1, value_2, with_precision",
    [_ + (True,) for _ in test_values_float_pairs]
    + [_ + (True,) for _ in test_values_float_int_pairs]
    + [_ + (False,) for _ in test_values_float_int_pairs],
)
def test_homomorphic_scalar_multiplication_type_error(
    value_1: int, value_2: Union[float, int], with_precision: bool
) -> None:
    """
    Test the multiplication of an encrypted value with a plaintext float value.
    This should throw an error, as the scheme does not support float scalars.

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.boot_generation()
    encrypted_value_2 = scheme.encrypt(value_2)
    scheme.shut_down()
    with pytest.raises(TypeError):
        _ = encrypted_value_2 * value_1


@pytest.mark.parametrize(
    "value_1, value_2, with_precision",
    [_ + (True,) for _ in test_values_float_int_pairs]
    + [_ + (False,) for _ in test_values_integer_pairs],
)
def test_homomorphic_scalar_multiplication(
    value_1: Union[float, int], value_2: int, with_precision: bool
) -> None:
    """
    Test the multiplication of an encrypted integer value with a plaintext integer value.

    :param value_1: to be encrypted plaintext value
    :param value_2: scalar value
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.boot_generation()
    fxp_1 = FixedPoint.fxp(value_1, scheme.precision)
    fxp_2 = FixedPoint.fxp(value_2, scheme.precision)
    encrypted_value_1 = scheme.encrypt(value_1)
    encrypted_prod_1 = encrypted_value_1 * value_2
    encrypted_prod_2 = value_2 * encrypted_value_1
    decrypted_prod_1 = scheme.decrypt(encrypted_prod_1)
    decrypted_prod_2 = scheme.decrypt(encrypted_prod_2)
    correct_prod = fxp_1 * fxp_2
    scheme.shut_down()
    assert correct_prod == decrypted_prod_1
    assert correct_prod == decrypted_prod_2


@pytest.mark.parametrize("with_precision", (True, False))
def test_plaintext_ints(with_precision: bool) -> None:
    """
    Test if the random_plaintext functionality produces values in the right range for schemes.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.shut_down()
    for _ in range(100):
        mask = scheme.random_plaintext()
        assert mask.precision == scheme.precision
        assert scheme.min_value <= mask <= scheme.max_value


def _test_time(with_precision: bool) -> None:
    """
    Determine the runtime of one encryption.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    start_time = time()
    for value in range(50):
        scheme.encrypt(value)
    test_time = time() - start_time
    print(test_time / 100)
    assert True
