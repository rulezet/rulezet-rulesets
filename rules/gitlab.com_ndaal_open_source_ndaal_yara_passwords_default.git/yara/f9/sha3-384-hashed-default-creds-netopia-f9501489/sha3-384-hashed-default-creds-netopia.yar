rule sha3_384_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="734336f2919c992320b8b4a2296e3619af30a1a33c99fd223af5e32611d6e5a844bfb33e23af8f7f9ae8d4894d90322b"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="c23021929ae92423cb46e50de33070cd268fa336ce2682a81cdcb02f97c2a1997efb8168393d90dbd6f4778d3da7c524"
    $a3="c23021929ae92423cb46e50de33070cd268fa336ce2682a81cdcb02f97c2a1997efb8168393d90dbd6f4778d3da7c524"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}