rule mysql41_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*EC7D0AAD3FC88DD649FBE66897A99081D20A26E7"
    $a3="*2E5A9F348A69E3728BDF95F06D42FEA7A05C7CCE"
    $a4="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a5="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a6="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a7="*60CE05C60319F4878B7A51EDF3DC98089E0C6E26"
    $a8="*A80082C9E4BB16D9C8E41B0D7EED46126DF4A46E"
    $a9="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a10="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a11="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a12="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a13="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a14="*FAAA67924961263057D0546413F1F88CE1793236"
    $a15="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}