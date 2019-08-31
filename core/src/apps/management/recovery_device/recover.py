from trezor.crypto import bip39, slip39
from trezor.errors import GroupThresholdReachedError, MnemonicError

from apps.common import storage

if False:
    from typing import Optional


class RecoveryAborted(Exception):
    pass


_GROUP_STORAGE_OFFSET = 16


def process_bip39(words: str) -> bytes:
    """
    Receives single mnemonic and processes it. Returns what is then stored
    in the storage, which is the mnemonic itself for BIP-39.
    """
    if not bip39.check(words):
        raise MnemonicError()
    return words.encode()


def process_slip39(words: str) -> Optional[bytes, int, int]:
    """
    Receives single mnemonic and processes it. Returns what is then stored in storage or
    None if more shares are needed.
    """
    mnemonic = slip39.decode_mnemonic(words)

    remaining = storage.recovery.fetch_slip39_remaining_shares()
    # TODO: move this whole logic to storage
    index_with_group_offset = (
        mnemonic.index + mnemonic.group_index * _GROUP_STORAGE_OFFSET
    )

    # if this is the first share, parse and store metadata
    if not remaining:
        storage.recovery.set_slip39_group_count(mnemonic.group_count)
        storage.recovery.set_slip39_group_threshold(mnemonic.group_threshold)
        storage.recovery.set_slip39_iteration_exponent(mnemonic.iteration_exponent)
        storage.recovery.set_slip39_identifier(mnemonic.identifier)
        storage.recovery.set_slip39_threshold(mnemonic.threshold)
        storage.recovery.set_slip39_remaining_shares(
            mnemonic.threshold - 1, mnemonic.group_index
        )
        storage.recovery_shares.set(index_with_group_offset, words)

        return None, mnemonic.group_index, mnemonic.index  # we need more shares

    if remaining[mnemonic.group_index] == 0:
        raise GroupThresholdReachedError()

    # These should be checked by UI before so it's a Runtime exception otherwise
    if mnemonic.identifier != storage.recovery.get_slip39_identifier():
        raise RuntimeError("Slip39: Share identifiers do not match")
    if storage.recovery_shares.get(index_with_group_offset):
        raise RuntimeError("Slip39: This mnemonic was already entered")

    remaining_for_share = (
        storage.recovery.get_slip39_remaining_shares(mnemonic.group_index)
        or mnemonic.threshold
    )
    storage.recovery.set_slip39_remaining_shares(
        remaining_for_share - 1, mnemonic.group_index
    )
    remaining[mnemonic.group_index] = remaining_for_share - 1
    storage.recovery_shares.set(index_with_group_offset, words)

    if remaining.count(0) < mnemonic.group_threshold:
        return None, mnemonic.group_index, mnemonic.index  # we need more shares

    if len(remaining) > 1:
        mnemonics = []
        for i, r in enumerate(remaining):
            # if we have multiple groups pass only the ones with threshold reached
            if r == 0:
                group = storage.recovery_shares.fetch_group(i)
                mnemonics.extend(group)
    else:
        mnemonics = storage.recovery_shares.fetch()

    identifier, iteration_exponent, secret = slip39.combine_mnemonics(mnemonics)
    return secret, mnemonic.group_index, mnemonic.index
