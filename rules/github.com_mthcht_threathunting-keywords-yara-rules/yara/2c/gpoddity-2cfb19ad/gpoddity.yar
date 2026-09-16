rule GPOddity
{
    meta:
        description = "Detection patterns for the tool 'GPOddity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GPOddity"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\'GPODDITY\$\'\s/ nocase ascii wide
                        $string2 = /\s\-\-gpo\-id\s.{0,100}\s\-\-domain\s.{0,100}\s\-\-command\s/ nocase ascii wide
                        $string3 = /\s\-\-gpo\-id\s.{0,100}\s\-\-gpo\-type\s.{0,100}\s\-\-no\-smb\-server\s/ nocase ascii wide
                        $string4 = " --rogue-smbserver-ip " nocase ascii wide
                        $string5 = " --rogue-smbserver-share " nocase ascii wide
                        $string6 = /\(not\slaunching\sGPOddity\sSMB\sserver\)/ nocase ascii wide
                        $string7 = /\/GPOddity\.git/ nocase ascii wide
                        $string8 = "/GPOddity/" nocase ascii wide
                        $string9 = /\[\!\]\sFailed\sto\sdownload\slegitimate\sGPO\sfrom\sSYSVOL\s\(dc_ip\:/ nocase ascii wide
                        $string10 = /\[\!\]\sFailed\sto\swrite\smalicious\sscheduled\stask\sto\sdownloaded\sGPO\.\sExiting/ nocase ascii wide
                        $string11 = /\[.{0,100}\]\sDownloading\sthe\slegitimate\sGPO\sfrom\sSYSVOL/ nocase ascii wide
                        $string12 = /\[.{0,100}\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO/ nocase ascii wide
                        $string13 = /\[.{0,100}\]\sUpdating\sdownloaded\sGPO\sversion\snumber\sto\sensure\sautomatic\sGPO\sapplication/ nocase ascii wide
                        $string14 = /\[\+\]\sSuccessfully\sdownloaded\slegitimate\sGPO\sfrom\sSYSVOL\sto\s/ nocase ascii wide
                        $string15 = /\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask/ nocase ascii wide
                        $string16 = /\[\+\]\sSuccessfully\sspoofed\sGPC\sgPCFileSysPath\sattribute/ nocase ascii wide
                        $string17 = /\\GPOddity\\/ nocase ascii wide
                        $string18 = "=== GENERATING MALICIOUS GROUP POLICY TEMPLATE ===" nocase ascii wide
                        $string19 = "46993522-7D77-4B59-9B77-F82082DE9D81" nocase ascii wide
                        $string20 = "Could not write NTLM Hashes to the specified JTR_Dump_Path " nocase ascii wide
                        $string21 = /Couldn\'t\sclone\sGPO\s\{\}\s\(maybe\sit\sdoes\snot\sexist\?/ nocase ascii wide
                        $string22 = /from\shelpers\..{0,100}_smbserver\s.{0,100}\simport\sSimpleSMBServer/ nocase ascii wide
                        $string23 = /gpoddity\.py/ nocase ascii wide
                        $string24 = /gpoddity_smbserver\.py/ nocase ascii wide
                        $string25 = "GPOddity-master" nocase ascii wide
                        $string26 = /helpers\.gpoddity_smbserver/ nocase ascii wide
                        $string27 = /If\sthe\sattack\sis\ssuccessful.{0,100}\syou\swill\ssee\sauthentication\slogs\sof\smachines\sretrieving\sand\sexecuting\sthe\smalicious\sGPO/ nocase ascii wide
                        $string28 = /\-\-just\-clean.{0,100}cleaning\/to_clean\.txt/ nocase ascii wide
                        $string29 = "LAUNCHING GPODDITY SMB SERVER AND WAITING FOR GPO REQUESTS" nocase ascii wide
                        $string30 = "net user john H4x00r123" nocase ascii wide
                        $string31 = /scheduledtask_utils\.py\s/ nocase ascii wide
                        $string32 = "SPOOFING GROUP POLICY TEMPLATE LOCATION THROUGH gPCFileSysPath" nocase ascii wide
                        $string33 = "synacktiv/GPOddity" nocase ascii wide
                        $string34 = "synacktiv_gpoddity" nocase ascii wide
                        $string35 = "You are trying to target a User Group Policy Object while running the embedded SMB server" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}