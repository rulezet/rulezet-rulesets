rule blake2b_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b23d988d4f9b76e98c7bcc821842946c9d2555586e715509e11826cde9ef3d506e1632420bc4de06c18fc53ea0d17920e0c1b4408e2891c2af518abd2d6f324"
    $a1="f1ff122d8d8d5655ec08af4ff601641a1c8fb703b5b370f6faf267d39412fa3452699eaccd26cab323812b5a0350b2b0ece3aed847385f7e7ae3febdba001ffb"
    $a2="7b23d988d4f9b76e98c7bcc821842946c9d2555586e715509e11826cde9ef3d506e1632420bc4de06c18fc53ea0d17920e0c1b4408e2891c2af518abd2d6f324"
    $a3="50032f97949698ca45e3fb1ed6b4a03b84a43eb5c1a2e1ae9d9432690740652db4f15d2a6f6787cced92bfa93d22a9a9b30c660f36a2246042c3b41185bf99ee"
    $a4="7b23d988d4f9b76e98c7bcc821842946c9d2555586e715509e11826cde9ef3d506e1632420bc4de06c18fc53ea0d17920e0c1b4408e2891c2af518abd2d6f324"
    $a5="01cc4e6c694668a0e8b645dd5b3fcdd9f2f768bd7f1634219698c040a8671371343e91baf7b0e081289d9392a099ddd6470c80714e140ac4932405cb611e8ba4"
    $a6="38b87a7cb8dbaed67f4a22bf16a2098fff56dbe813363739a8310ae55ee506c01e27cf78a48f8c34c36d428c5ae4363f577baf6b2a7ebcf736b4506c082e1158"
    $a7="9ef332732b6811d22395262813a1666b4c183a24138b22d2b0c7eb97ec23c745439b8242aca59df64c270c0bd561ac9d1b2b85a0c915ada4dde4afef7eadacb8"
    $a8="953356f07bcfd347bcd4df72861aa54771c87947526ab5ea7b1c5f9676e436e0c46984591883647cd9fc2dbf68388935bafd5c34d54e52e69a854da431cdd952"
    $a9="953356f07bcfd347bcd4df72861aa54771c87947526ab5ea7b1c5f9676e436e0c46984591883647cd9fc2dbf68388935bafd5c34d54e52e69a854da431cdd952"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}