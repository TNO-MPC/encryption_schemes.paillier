"""
Implementation of the Paillier cryptosystem.
"""

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
from .paillier import Paillier as Paillier
from .paillier import PaillierCiphertext as PaillierCiphertext
from .paillier import PaillierSecretKey as PaillierSecretKey
from .paillier import PaillierPublicKey as PaillierPublicKey

__version__ = "0.4.3"
