rule sha384_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a055b36f9947efb7fbe1817e20e14d5f4c4815a0d51b089f1fafa2e7cc8909b840b8e455dd740ce6313fa56419ad86f"
    $a1="0b0920075996b936192ff5550f153b2c845184834abf13fb67ba8dc07ff728d7c1a809919d044de3974d14a18c1d6e67"
    $a2="f90af180966a30a4bb42c9a2e5390e12279336d0355d26c5746219a2d5d2cc60793fecdd3ee224cc0041678d2238159f"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="683efc8fb8cdedb8e52255891bdfb91afad01b7d31b746a0ecdb8760d9e334365338ab5943f35e22c424ec3c65fa4404"
    $a7="66e17cee68b63148b492c1e60cc3b9c85161eac639df6ccc878f251b056eb1a1994c6e81f1f6971a3ada23434c9c5ef2"
    $a8="0d2542695647320ec0bedbd6a467fa94320835293536b8d12903950e6d0df65c6861f98eedb45f48fcc71496fb2f9a80"
    $a9="f507f1638f8d1ed7fd34b4f6ebac79309f2ed1bfa785ae3d6558a701c8af466af6ef1a9ae260bb0196039ce2c7d6b514"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}