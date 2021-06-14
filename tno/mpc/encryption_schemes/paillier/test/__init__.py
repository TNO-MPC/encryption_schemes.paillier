"""
Testing module of the tno.mpc.encryption_schemes.paillier library
"""

from tno.mpc.encryption_schemes.paillier import Paillier


def paillier_scheme(with_precision: bool) -> Paillier:
    """
    Constructs a Paillier scheme

    :param with_precision: boolean specifying whether to use precision in scheme
    :return: Initialized Paillier scheme with, or without, precision
    """
    if with_precision:
        return Paillier.from_security_parameter(
            key_length=1024,
            precision=10,
            nr_of_threads=3,
            debug=False,
            start_generation=False,
        )
    return Paillier.from_security_parameter(
        key_length=1024, nr_of_threads=3, debug=False, start_generation=False
    )
