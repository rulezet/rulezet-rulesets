rule sha512_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8acda221280c5684a907eee7a8b96f88025b2815c03ee2ffefbc51f221d6197d44f01621c9420d45e93c876aea090813dd3f5182d202c1cef036e3a5651a393a"
    $a1="8acda221280c5684a907eee7a8b96f88025b2815c03ee2ffefbc51f221d6197d44f01621c9420d45e93c876aea090813dd3f5182d202c1cef036e3a5651a393a"
    $a2="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a3="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a4="5f9311fa05854c9357d2fa4ab0b0db37b50481e0e7e907cb048da771b534037cf279e22161091c4b7131d1210ed402c8a744595f7d614683db0994f27000d15b"
    $a5="5f9311fa05854c9357d2fa4ab0b0db37b50481e0e7e907cb048da771b534037cf279e22161091c4b7131d1210ed402c8a744595f7d614683db0994f27000d15b"
    $a6="efd22db8c6e2bbacf88bdcf49b91831d2398e63bfebf519824e68682ba9f9549506fbc34b49008a50a8d9ed59cec5fb0b3caea7590d3ef9feebc77b542dadcbb"
    $a7="efd22db8c6e2bbacf88bdcf49b91831d2398e63bfebf519824e68682ba9f9549506fbc34b49008a50a8d9ed59cec5fb0b3caea7590d3ef9feebc77b542dadcbb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}