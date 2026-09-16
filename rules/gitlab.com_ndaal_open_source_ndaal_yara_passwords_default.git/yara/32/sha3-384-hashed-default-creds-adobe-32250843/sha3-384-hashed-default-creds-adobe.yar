rule sha3_384_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="255eaaa0c3500178d298bdc7a8cf838a0325a42219ee399b637d127fc9e905100d993eddb0d3a7946c886ee5b778e595"
    $a3="255eaaa0c3500178d298bdc7a8cf838a0325a42219ee399b637d127fc9e905100d993eddb0d3a7946c886ee5b778e595"
    $a4="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a5="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a6="8406dc06cf7a0dd50e5aaab4cd139cf4de13c443cefafe8eb5e3f33b2dcf25b352fa727efa7040a99ba3c242be594c42"
    $a7="21cbb085b4ce02709b1675982cf5ce4746f94f1904fad6bb8aaedb15cf930a1f41da52d79ef035a728b388458978662f"
    $a8="e346c867abaaa932275181b81141778226c6499e1db02e982edb89458906cc41995bcce2c0931e31e8fbb4525b701074"
    $a9="f2b6125cb326430278414ae56a7ec1b3e799479d172c481a0e2e7250b616eca4bd3cae12ab4f588b44468330a463239f"
    $a10="887c3e142959c3e9a58ae96faf9d85169d2f50f7f05672e13311d5631b73d4e4d7678df52b99b560ac6aaa47b18ef5a5"
    $a11="887c3e142959c3e9a58ae96faf9d85169d2f50f7f05672e13311d5631b73d4e4d7678df52b99b560ac6aaa47b18ef5a5"
    $a12="5bbf4565114af861a43adebf24140520ec1495883c55ea4886bc6eb7c97a512bcaef86298878792f0d7130a65d9d815b"
    $a13="5bbf4565114af861a43adebf24140520ec1495883c55ea4886bc6eb7c97a512bcaef86298878792f0d7130a65d9d815b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}