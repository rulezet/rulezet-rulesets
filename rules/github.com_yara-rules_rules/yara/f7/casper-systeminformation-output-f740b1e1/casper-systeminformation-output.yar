rule Casper_SystemInformation_Output
{

    meta:
        description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/06"
        score = 70

    strings:
        $a0 = "***** SYSTEM INFORMATION ******"
        $a1 = "***** SECURITY INFORMATION ******"
        $a2 = "Antivirus: "
        $a3 = "Firewall: "
        $a4 = "***** EXECUTION CONTEXT ******"
        $a5 = "Identity: "
        $a6 = "<CONFIG TIMESTAMP="

    condition:
        all of them
}