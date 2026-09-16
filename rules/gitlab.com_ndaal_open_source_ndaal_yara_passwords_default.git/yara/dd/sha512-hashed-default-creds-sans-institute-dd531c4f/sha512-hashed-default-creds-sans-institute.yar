rule sha512_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18e8e49e8803e804454c42dacd1dbebfb1524a244b9fec3347fb1eeb9714ef0d0e813900f663c0398c6e4e344544ff396be81d92db3b782bc1ab349d16cf3e84"
    $a1="d280e89dc6f2d4ab38a13633da7cf38bf7adafbc7bf1941e95ec182f8d3e0b68a649ff732be7dee4e15851dd2d383c2339cf9f069490c38d804260213b04e84d"
condition:
    ($a0 and $a1)
}