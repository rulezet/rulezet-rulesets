rule blake2s_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a740d7e996aa82241f2484b1337afdfb6cc6b7ef4045ea83b9e47ba0104e949"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="334b0ca2d64b32b82cfe1857e6d9ffe07896f630dca6602e2c32b7901293a758"
    $a3="d1e09d6ed41d3d01aef6d3db8a4c7fcba16ef21b5768e365062f57c168c4a8ae"
    $a4="a623fe8afc873a57c6a4c5a884031d72aad39e8cb2c1409792254325836d6621"
    $a5="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a6="420cec69e54b2fc0bb3e50d1c1e2e38ab991afee1bcc457fed70915a13fc0c20"
    $a7="0fa2f331d3c86ff7af4b1ea1b6f2c7db4bdeffc24fb646cd1ffb8a8fe91f776f"
    $a8="f65651439abadd7c269c010fa95c0cda02c17f1daec30025405216dee1818690"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a12="815aaf0b2d8d3e193a9fa163a65fb90cc565a386e43e670c4905f47a11a5ec9b"
    $a13="930b1ff490516eb57486c34411040611a9254820cfa0e08a22bc80aa8647c309"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}