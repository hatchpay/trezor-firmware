from trezor import wire
from trezor.messages.Success import Success
from trezor.messages.WebAuthnAddResidentCredentials import WebAuthnAddResidentCredential
from trezor.ui.text import Text

from apps.common.confirm import require_confirm
from apps.common.storage.webauthn import store_resident_credential
from apps.webauthn.credential import Fido2Credential


async def add_resident_credential(
    ctx: wire.Context, msg: WebAuthnAddResidentCredential
) -> Success:
    if not msg.credetial_id:
        raise wire.ProcessError("Missing credential ID parameter.")

    text = Text("Add credentials")
    text.normal(
        "Do you really want to", "import resident", "credentials into the", "device?"
    )
    await require_confirm(ctx, text)

    cred = Fido2Credential.from_cred_id(msg.credetial_id, None)
    if cred is not None:
        store_resident_credential(cred)
    return Success(message="Credentials added")
