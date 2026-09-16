rule sha3_512_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a1="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a2="d95819f4caa17f3fe91cc5220ec3b849ea2cbd68068968054ad50dc5dac42b7407bf1bc56bd8adf4cca0238aa349643da935921317d94c5fcbdfce918a078738"
    $a3="d95819f4caa17f3fe91cc5220ec3b849ea2cbd68068968054ad50dc5dac42b7407bf1bc56bd8adf4cca0238aa349643da935921317d94c5fcbdfce918a078738"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}