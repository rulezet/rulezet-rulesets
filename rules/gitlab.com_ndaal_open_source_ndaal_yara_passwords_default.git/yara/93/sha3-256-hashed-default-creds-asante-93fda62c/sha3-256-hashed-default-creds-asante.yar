rule sha3_256_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abfeafd656b5a18206092fa00e2df04c821b8cf7d168c0769492bd9764435474"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="abfeafd656b5a18206092fa00e2df04c821b8cf7d168c0769492bd9764435474"
    $a3="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
    $a4="835013eb39d3e3f3f53c6803f10cd82aa9f153e96d725ee858691a1944f9749b"
    $a5="0d6efbb9065510471bb1783ef3db93c06f476b894af603b46fcdfb692e1d36b7"
    $a6="835013eb39d3e3f3f53c6803f10cd82aa9f153e96d725ee858691a1944f9749b"
    $a7="cf4a073d1685377e9a96df1d897f90bc429ade355bf50d2b959679d562ae620e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}