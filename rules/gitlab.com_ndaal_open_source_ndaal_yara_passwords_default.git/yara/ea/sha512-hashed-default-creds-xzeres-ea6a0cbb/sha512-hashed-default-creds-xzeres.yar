rule sha512_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da75acad5566bf640b2734140b546efe1b7115af33f2e87867d3d71e6b7939eeb9cff083f747500281da3cca46a4be217a9df90842481526a6afbc18aed3e185"
    $a1="754a07b4c5e5976695a1e8d4220c30167d9ad299e292d91e1fd21da6abe79f383e74a75d81cf5c46f783cff99fcc9114a1772fb2bbc779f9bf4571575811a240"
condition:
    ($a0 and $a1)
}