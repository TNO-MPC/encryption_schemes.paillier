"""
Test integration with tno.mpc.communication module.
"""

from __future__ import annotations

from typing import Any

import pytest

from tno.mpc.communication import Pool

from tno.mpc.encryption_schemes.paillier import (
    Paillier,
    PaillierCiphertext,
    PaillierPublicKey,
    PaillierSecretKey,
)


async def send_and_receive(pools: tuple[Pool, Pool], obj: Any) -> Any:
    """
    Method that sends objects from one party to another.

    :param pools: collection of communication pools
    :param obj: object to be sent
    :return: the received object
    """
    # send from host 1 to host 2
    await pools[0].send(pools[1].name, obj)
    return await pools[1].recv(pools[0].name)


@pytest.mark.asyncio
async def test_sending_and_receiving_paillierpublickey(
    mock_pool_duo: tuple[Pool, Pool],
) -> None:
    """
    Ensures that PaillierPublicKey serialization logic is correctly loaded into the communication
    module.

    :param mock_pool_duo: Fixture with mock communication pools.
    """
    public_key = PaillierPublicKey(n=11, g=22)
    public_key_prime = await send_and_receive(mock_pool_duo, public_key)
    assert public_key == public_key_prime


@pytest.mark.asyncio
async def test_sending_and_receiving_pailliersecretkey(
    mock_pool_duo: tuple[Pool, Pool],
) -> None:
    """
    Ensures that PaillierSecretKey serialization logic is correctly loaded into the communication
    module.

    :param mock_pool_duo: Fixture with mock communication pools.
    """
    secret_key = PaillierSecretKey(lambda_=11, mu=22, n=33)
    secret_key_prime = await send_and_receive(mock_pool_duo, secret_key)
    assert secret_key == secret_key_prime


@pytest.mark.asyncio
async def test_sending_and_receiving_paillier(
    mock_pool_duo: tuple[Pool, Pool], scheme: Paillier
) -> None:
    """
    Ensures that Paillier serialization logic is correctly loaded into the communication module.

    :param mock_pool_duo: Fixture with mock communication pools.
    :param scheme: Scheme under test.
    """
    scheme_prime = await send_and_receive(mock_pool_duo, scheme)
    assert scheme_prime is scheme


@pytest.mark.asyncio
async def test_sending_and_receiving_paillierciphertext(
    mock_pool_duo: tuple[Pool, Pool], ciphertext: PaillierCiphertext
) -> None:
    """
    Ensures that PaillierCiphertext serialization logic is correctly loaded into the communication
    module.

    :param mock_pool_duo: Fixture with mock communication pools.
    :param ciphertext: Ciphertext scheme under test.
    """
    ciphertext_prime = await send_and_receive(mock_pool_duo, ciphertext)
    assert ciphertext == ciphertext_prime
