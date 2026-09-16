rule sha512_hashed_default_creds_airaya_corp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for airaya_corp."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85b09c5aabb8e42383a1acbc7a7f468bf86f64f48790fd4f87f61efc9f54b91cadf5804d9be927cd87eacee265cdc0db46469ec3495da9cd71098b063cdf06d1"
    $a1="85b09c5aabb8e42383a1acbc7a7f468bf86f64f48790fd4f87f61efc9f54b91cadf5804d9be927cd87eacee265cdc0db46469ec3495da9cd71098b063cdf06d1"
condition:
    ($a0 and $a1)
}