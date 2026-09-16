rule Bat_Relaunch_Hidden
{
    meta:
        author = "k3rnelcallz"
        description = "malicious bat runs in hidden mode"
        sha = "7a3962542b2a4b3f2b4d157c2efbcfaba87f347419de7b2671b84be71c93234e"
        tags = "Koadic"
        
    strings:
        $ = "!RANDZIP!.zip"
        $ = "-WindowStyle Hidden"
        $ = "pdfFile"
        $ = "\\Contacts\\Stdwk"
        $ = "\\Contacts\\!RANDZIP!.zip"
        $ = "\\Contacts\\!RANDZIP!.zip"
        $ = "\\Contacts\\!RANDSTZIP!.zip"
        $ = "\\Contacts\\doku"
        $ = "\\Contacts\\!RANDSTARTUP!.bat"
        $ = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        $ = "FromBase64String"
        $ = "%STARTUPBATCPY%"

    condition:
        all of them
}