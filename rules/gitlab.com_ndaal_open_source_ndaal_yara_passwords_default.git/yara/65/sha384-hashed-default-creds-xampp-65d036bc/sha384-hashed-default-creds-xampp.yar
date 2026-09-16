rule sha384_hashed_default_creds_xampp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2483236e15afac35920898385ba3e2ec3b55f0fe886460efebc9af582cccce387b45db0c2752ed30dfd9b659230dde8e"
    $a1="db8d4dde8910796663a37f48af49cc9b5d3d68bc7adece1ec267ade0a21bef7a0c40ce8e14d09d2b28e37d7b9a047811"
condition:
    ($a0 and $a1)
}