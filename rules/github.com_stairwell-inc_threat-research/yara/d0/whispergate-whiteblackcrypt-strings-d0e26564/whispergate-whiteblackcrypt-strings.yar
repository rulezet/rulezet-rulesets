rule WhisperGate_WhiteBlackCrypt_strings
{
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Matches strings seen in WhiteBlackCrypt"
        ref = "https://cip.gov.ua/ua/news/informaciya-shodo-imovirnoyi-provokaciyi"
        version = "0.1"
    strings:
        $ = ".encrpt3d"
        $ = "C:\\ProgramData\\CheckServiceD.exe"
        $ = "HOMEDRIVE"
        $ = "ye64T0p"
        $ = "USERPROFILE"
        $ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        5 of them    
}