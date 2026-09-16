rule sha3_384_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8354fd6700889606475262f1c2594921dc0cdeb891beb5bdf8e21a803bdc4c4e1bef774f86b30e6adbb5eeb0979a7d39"
    $a1="8354fd6700889606475262f1c2594921dc0cdeb891beb5bdf8e21a803bdc4c4e1bef774f86b30e6adbb5eeb0979a7d39"
    $a2="a695cbbc6ba7f0442f5acee0f756cd6057cfc50d1383fcec2507717b4a4346929cf5f8aa2b44e67d3bdaddbcacb04ece"
    $a3="a695cbbc6ba7f0442f5acee0f756cd6057cfc50d1383fcec2507717b4a4346929cf5f8aa2b44e67d3bdaddbcacb04ece"
    $a4="860253787ae9161f3b72e689582d2beaebc1cdfb521053f2ba12ad3db10ce677f2323171e205f82668d109d818bbf16a"
    $a5="860253787ae9161f3b72e689582d2beaebc1cdfb521053f2ba12ad3db10ce677f2323171e205f82668d109d818bbf16a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}