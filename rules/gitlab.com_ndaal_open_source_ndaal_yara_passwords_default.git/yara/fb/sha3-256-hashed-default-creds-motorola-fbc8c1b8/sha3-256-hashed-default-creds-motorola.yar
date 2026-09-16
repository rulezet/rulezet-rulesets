rule sha3_256_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae48964325684403f4239ebf3de09bea8dce035f40ffc0c03959300538f476bd"
    $a1="edac5c28b92c7d127bd2b5557d6ee6a2491cc147103ee5fb16bd39100ff30c58"
    $a2="34f06ccb589e19284e83e1669bae6358d6a4c6b23698dc3114b94adfd53faac9"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="ed9e36fa06a282d0572283f9332e1008e159ec1d234e55fc4316c7fa0f3f30d2"
    $a7="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a8="a7797efa8ce0417f3f0242d74182c431c6a6b5c739348afb3b01d8c11cce36b2"
    $a9="92a2396ac62ab41d712a66589901cb680160f38cfe0359b0f0d35f6b5d35251a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}