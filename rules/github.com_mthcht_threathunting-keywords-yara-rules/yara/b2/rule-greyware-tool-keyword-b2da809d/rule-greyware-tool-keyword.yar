rule rule___greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '_' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "_"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1___greyware_tool_keyword = " ecivreS-potS" nocase ascii wide
                        $string2___greyware_tool_keyword = " gifnoc cs" nocase ascii wide
                        $string3___greyware_tool_keyword = " noitcetorPAUP" nocase ascii wide
                        $string4___greyware_tool_keyword = "%tooRmetsyS%" nocase ascii wide
                        $string5___greyware_tool_keyword = /\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\Windows\\System32\\cmd\.exe/ nocase ascii wide
                        $string6___greyware_tool_keyword = /\/keygen\.exe/ nocase ascii wide
                        $string7___greyware_tool_keyword = /\/PAYMENTS\.exe/ nocase ascii wide
                        $string8___greyware_tool_keyword = /\\1\.bat/ nocase ascii wide
                        $string9___greyware_tool_keyword = /\\1\.dll/ nocase ascii wide
                        $string10___greyware_tool_keyword = /\\1\.exe/ nocase ascii wide
                        $string11___greyware_tool_keyword = /\\2\.bat/ nocase ascii wide
                        $string12___greyware_tool_keyword = /\\2\.dll/ nocase ascii wide
                        $string13___greyware_tool_keyword = /\\2\.exe/ nocase ascii wide
                        $string14___greyware_tool_keyword = /\\3\.bat/ nocase ascii wide
                        $string15___greyware_tool_keyword = /\\3\.dll/ nocase ascii wide
                        $string16___greyware_tool_keyword = /\\3\.exe/ nocase ascii wide
                        $string17___greyware_tool_keyword = /\\4\.bat/ nocase ascii wide
                        $string18___greyware_tool_keyword = /\\4\.dll/ nocase ascii wide
                        $string19___greyware_tool_keyword = /\\4\.exe/ nocase ascii wide
                        $string20___greyware_tool_keyword = /\\5\.bat/ nocase ascii wide
                        $string21___greyware_tool_keyword = /\\5\.dll/ nocase ascii wide
                        $string22___greyware_tool_keyword = /\\5\.exe/ nocase ascii wide
                        $string23___greyware_tool_keyword = /\\6\.bat/ nocase ascii wide
                        $string24___greyware_tool_keyword = /\\6\.dll/ nocase ascii wide
                        $string25___greyware_tool_keyword = /\\6\.exe/ nocase ascii wide
                        $string26___greyware_tool_keyword = /\\7\.bat/ nocase ascii wide
                        $string27___greyware_tool_keyword = /\\7\.dll/ nocase ascii wide
                        $string28___greyware_tool_keyword = /\\7\.exe/ nocase ascii wide
                        $string29___greyware_tool_keyword = /\\8\.bat/ nocase ascii wide
                        $string30___greyware_tool_keyword = /\\8\.dll/ nocase ascii wide
                        $string31___greyware_tool_keyword = /\\8\.exe/ nocase ascii wide
                        $string32___greyware_tool_keyword = /\\9\.bat/ nocase ascii wide
                        $string33___greyware_tool_keyword = /\\9\.dll/ nocase ascii wide
                        $string34___greyware_tool_keyword = /\\9\.exe/ nocase ascii wide
                        $string35___greyware_tool_keyword = /\\AppData\\Local\\Temp\\a\.exe/ nocase ascii wide
                        $string36___greyware_tool_keyword = /\\AppData\\Local\\Temp\\b\.exe/ nocase ascii wide
                        $string37___greyware_tool_keyword = /\\AppData\\Local\\Temp\\c\.exe/ nocase ascii wide
                        $string38___greyware_tool_keyword = /\\AppData\\Local\\Temp\\d\.exe/ nocase ascii wide
                        $string39___greyware_tool_keyword = /\\AppData\\Local\\Temp\\e\.exe/ nocase ascii wide
                        $string40___greyware_tool_keyword = /\\AppData\\Local\\Temp\\f\.exe/ nocase ascii wide
                        $string41___greyware_tool_keyword = /\\AppData\\Local\\Temp\\g\.exe/ nocase ascii wide
                        $string42___greyware_tool_keyword = /\\AppData\\Local\\Temp\\h\.exe/ nocase ascii wide
                        $string43___greyware_tool_keyword = /\\AppData\\Local\\Temp\\i\.exe/ nocase ascii wide
                        $string44___greyware_tool_keyword = /\\AppData\\Local\\Temp\\j\.exe/ nocase ascii wide
                        $string45___greyware_tool_keyword = /\\AppData\\Local\\Temp\\k\.exe/ nocase ascii wide
                        $string46___greyware_tool_keyword = /\\AppData\\Local\\Temp\\l\.exe/ nocase ascii wide
                        $string47___greyware_tool_keyword = /\\AppData\\Local\\Temp\\m\.exe/ nocase ascii wide
                        $string48___greyware_tool_keyword = /\\AppData\\Local\\Temp\\n\.exe/ nocase ascii wide
                        $string49___greyware_tool_keyword = /\\AppData\\Local\\Temp\\o\.exe/ nocase ascii wide
                        $string50___greyware_tool_keyword = /\\AppData\\Local\\Temp\\p\.exe/ nocase ascii wide
                        $string51___greyware_tool_keyword = /\\AppData\\Local\\Temp\\q\.exe/ nocase ascii wide
                        $string52___greyware_tool_keyword = /\\AppData\\Local\\Temp\\r\.exe/ nocase ascii wide
                        $string53___greyware_tool_keyword = /\\AppData\\Local\\Temp\\s\.exe/ nocase ascii wide
                        $string54___greyware_tool_keyword = /\\AppData\\Local\\Temp\\t\.exe/ nocase ascii wide
                        $string55___greyware_tool_keyword = /\\AppData\\Local\\Temp\\u\.exe/ nocase ascii wide
                        $string56___greyware_tool_keyword = /\\AppData\\Local\\Temp\\v\.exe/ nocase ascii wide
                        $string57___greyware_tool_keyword = /\\AppData\\Local\\Temp\\w\.exe/ nocase ascii wide
                        $string58___greyware_tool_keyword = /\\AppData\\Local\\Temp\\x\.exe/ nocase ascii wide
                        $string59___greyware_tool_keyword = /\\AppData\\Local\\Temp\\y\.exe/ nocase ascii wide
                        $string60___greyware_tool_keyword = /\\AppData\\Local\\Temp\\z\.exe/ nocase ascii wide
                        $string61___greyware_tool_keyword = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,100}\.bat/ nocase ascii wide
                        $string62___greyware_tool_keyword = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,100}\.cmd/ nocase ascii wide
                        $string63___greyware_tool_keyword = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,100}\.hta/ nocase ascii wide
                        $string64___greyware_tool_keyword = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,100}\.ps1/ nocase ascii wide
                        $string65___greyware_tool_keyword = /\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,100}\.vbs/ nocase ascii wide
                        $string66___greyware_tool_keyword = /\\keygen\.exe/ nocase ascii wide
                        $string67___greyware_tool_keyword = /\\PAYMENT\.hta/ nocase ascii wide
                        $string68___greyware_tool_keyword = /\\PAYMENT\.hta/ nocase ascii wide
                        $string69___greyware_tool_keyword = /\\PAYMENTS\.exe/ nocase ascii wide
                        $string70___greyware_tool_keyword = /c\/\sexe\.dmc/ nocase ascii wide
                        $string71___greyware_tool_keyword = /c\:\\.{0,100}\\\\u0.{0,100}\\\\u0.{0,100}\\\\u0.{0,100}\\\\u0/ nocase ascii wide
                        $string72___greyware_tool_keyword = "delbasiD epyTputratS- " nocase ascii wide
                        $string73___greyware_tool_keyword = "ecnereferPpM-teS" nocase ascii wide
                        $string74___greyware_tool_keyword = "eliforPllaweriFteN-teS" nocase ascii wide
                        $string75___greyware_tool_keyword = /exe\.23lldnur/ nocase ascii wide
                        $string76___greyware_tool_keyword = /exe\.erolpxei/ nocase ascii wide
                        $string77___greyware_tool_keyword = /exe\.rerolpxe/ nocase ascii wide
                        $string78___greyware_tool_keyword = /exe\.ssasl/ nocase ascii wide
                        $string79___greyware_tool_keyword = /exe\.tsohcvs/ nocase ascii wide
                        $string80___greyware_tool_keyword = "gnirotinoMemitlaeRelbasiD" nocase ascii wide
                        $string81___greyware_tool_keyword = "llawerifvda hsten" nocase ascii wide
                        $string82___greyware_tool_keyword = /niB\.elcyceR\$/ nocase ascii wide
                        $string83___greyware_tool_keyword = "teSlortnoCtnerruC" nocase ascii wide
                        $string84___greyware_tool_keyword = /https\:\/\/.{0,100}\.xyz\/.{0,100}\.ps1/ nocase ascii wide
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