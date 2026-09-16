rule sha384_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0390eaa4c16ec73e0cb8f759a497d30ad449b6f11637c85457a6de0b63e456c863bc991b9cf0f83c373453c7e058cc76"
    $a1="0390eaa4c16ec73e0cb8f759a497d30ad449b6f11637c85457a6de0b63e456c863bc991b9cf0f83c373453c7e058cc76"
    $a2="5e5b054a1371434a3150ff26014bab146b50c563d6ea364b82d72d796197a475c3728cee12a5360def4a10766241f37b"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="3fe35e481a78c49434a85ead9d705ed62919749d5e766cd2d6ef060127181ca83cd4087b6e11644b2f09a3957fb78c7c"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}