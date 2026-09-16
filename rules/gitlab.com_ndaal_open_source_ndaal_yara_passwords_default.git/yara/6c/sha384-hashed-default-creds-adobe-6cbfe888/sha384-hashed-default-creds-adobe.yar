rule sha384_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="fc295a302b9b9fe4b244696d373be482c16543f00e15c127296926ee41a5969e5b9696927698bbc1b44a3547e303e306"
    $a3="fc295a302b9b9fe4b244696d373be482c16543f00e15c127296926ee41a5969e5b9696927698bbc1b44a3547e303e306"
    $a4="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a5="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a6="0f15c359d1f4e9588316f37364fdca3864a8bc93b245d669262673d7fdb385a9b668d3c2e08d849cb01717282d101358"
    $a7="c00c73d64a94b012680430e9a1241bed72a2e396de9f10a2f6b90a16c3654b198c31899174a09b839782c3e47f96eb95"
    $a8="1575fda7121294efb03433bb56065850cc2d37d6c90300df06ebe6734273e44119bafb13b07835ea87ef79ea9f288dcb"
    $a9="8f898489836435195a82c599aedfdad6f159df00c370fbd477b508e5504cbc20073cdfae69213f91183d69a7b4edc391"
    $a10="03fdbeadf6993c5788b0fe6fd8f7da64186f787512af18b9b1322751b8a5fca0f900204896ddcf5e33b45e515974f38a"
    $a11="03fdbeadf6993c5788b0fe6fd8f7da64186f787512af18b9b1322751b8a5fca0f900204896ddcf5e33b45e515974f38a"
    $a12="6b88d88c864297536657c231b5904bf7528524267675c39565b8b8645948875cdc15f50cb2a19766e36db126d1b26cd1"
    $a13="6b88d88c864297536657c231b5904bf7528524267675c39565b8b8645948875cdc15f50cb2a19766e36db126d1b26cd1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}