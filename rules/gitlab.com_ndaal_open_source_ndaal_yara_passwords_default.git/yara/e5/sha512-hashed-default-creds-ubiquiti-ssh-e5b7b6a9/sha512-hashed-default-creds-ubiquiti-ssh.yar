rule sha512_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="9a9a1b637cf31e2b159b512c24d3fae2407e2dcf15026c23a19d8828dca4d1b95f32cb78dbd87648afeb9281dee909b37e638e8b971f918579a5e756cafdecb7"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="9a9a1b637cf31e2b159b512c24d3fae2407e2dcf15026c23a19d8828dca4d1b95f32cb78dbd87648afeb9281dee909b37e638e8b971f918579a5e756cafdecb7"
    $a5="9a9a1b637cf31e2b159b512c24d3fae2407e2dcf15026c23a19d8828dca4d1b95f32cb78dbd87648afeb9281dee909b37e638e8b971f918579a5e756cafdecb7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}