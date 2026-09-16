rule sha512_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8f8e7789282abaf2e2af29ef7316b1a9881cfde07fd929f22227fcfccc48bbdd88d5881a41057fdb4dced0c6d349780ea7dadc0d0444c49681f0422fac51a23"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="f8f8e7789282abaf2e2af29ef7316b1a9881cfde07fd929f22227fcfccc48bbdd88d5881a41057fdb4dced0c6d349780ea7dadc0d0444c49681f0422fac51a23"
    $a3="e84b372bbef62b552b98b7d54c7339841e2bf687a7cabefc8c76205da7f2dda67cfdbc3776d80224ea38825aa501b5bf88d05075e8b5441e62220c013463fbbc"
    $a4="4a3103085e438b82cc2d7bee8abe9a7a15964051386bbd06f5187d562e98f2255c870f400ff1a47f7621c23bfb8b3dd67f069b11cec8c3fdf5ef48e2d5010c84"
    $a5="d005ba24545146557756c648a09c16305b59a65fa091da96e856ebc8800b0ddf3cf14cbe1871a3b2f1ea8e7c6fbe0d015de6fc3961a18b39a328934f0fc6a7d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}