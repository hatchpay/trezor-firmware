from trezor import wire
from trezor.messages.Success import Success
from trezor.messages.WebAuthnRemoveResidentCredentials import (
    WebAuthnRemoveResidentCredential,
)
from trezor.ui.text import Text

from apps.common.confirm import require_confirm
from apps.common.storage.webauthn import erase_resident_credential


async def remove_resident_credential(
    ctx: wire.Context, msg: WebAuthnRemoveResidentCredential
) -> Success:
    if msg.index is None:
        raise wire.ProcessError("Missing credential index parameter.")

    text = Text("Remove credentials")
    text.normal(
        "Do you really want to", "remove resident", "credentials from the", "device?"
    )
    await require_confirm(ctx, text)

    erase_resident_credential(msg.index)
    return Success(message="Credentials removed")
