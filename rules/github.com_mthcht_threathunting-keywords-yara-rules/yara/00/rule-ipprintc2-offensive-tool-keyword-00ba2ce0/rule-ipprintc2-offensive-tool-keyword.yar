rule rule_IPPrintC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IPPrintC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IPPrintC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IPPrintC2_offensive_tool_keyword = /\sIPPrintC2\.ps1/ nocase ascii wide
                        $string2_IPPrintC2_offensive_tool_keyword = "\"IPPrint C2 Server\"" nocase ascii wide
                        $string3_IPPrintC2_offensive_tool_keyword = /\$C2ExternalIP\s\=\s/ nocase ascii wide
                        $string4_IPPrintC2_offensive_tool_keyword = /\$C2ExternalIP/ nocase ascii wide
                        $string5_IPPrintC2_offensive_tool_keyword = /\$C2Output\@\$date\.pdf/ nocase ascii wide
                        $string6_IPPrintC2_offensive_tool_keyword = /\$EncodedCommandExfil/ nocase ascii wide
                        $string7_IPPrintC2_offensive_tool_keyword = /\$IPPrintC2\s\=\s/ nocase ascii wide
                        $string8_IPPrintC2_offensive_tool_keyword = /\$IPPrintC2/ nocase ascii wide
                        $string9_IPPrintC2_offensive_tool_keyword = /\$IPPrintC2\.DocumentName/ nocase ascii wide
                        $string10_IPPrintC2_offensive_tool_keyword = /\$IPPrintC2\.Print/ nocase ascii wide
                        $string11_IPPrintC2_offensive_tool_keyword = /\(Invoke\-WebRequest\s\-Uri\s\\"https\:\/\/ifconfig\.me\/ip\\"\)\.Content/ nocase ascii wide
                        $string12_IPPrintC2_offensive_tool_keyword = /\/IPPrintC2\.git/ nocase ascii wide
                        $string13_IPPrintC2_offensive_tool_keyword = /\/IPPrintC2\.git/ nocase ascii wide
                        $string14_IPPrintC2_offensive_tool_keyword = /\/IPPrintC2\.ps1/ nocase ascii wide
                        $string15_IPPrintC2_offensive_tool_keyword = /\[System\.Text\.Encoding\]\:\:Unicode\.GetBytes\(\\"\[scriptblock\].{0,100}\$x\=\{\$CommandDoc\}\;.{0,100}\$x\.Invoke\(\)/ nocase ascii wide
                        $string16_IPPrintC2_offensive_tool_keyword = /\\\\DESKTOP\-PRINTINGFUN/ nocase ascii wide
                        $string17_IPPrintC2_offensive_tool_keyword = /\\IPPrintC2\.ps1/ nocase ascii wide
                        $string18_IPPrintC2_offensive_tool_keyword = "49656d058f63398c98cff95a5bbe76a6911e003ddb7baea082a7e7752525d6a6" nocase ascii wide
                        $string19_IPPrintC2_offensive_tool_keyword = "4c02774a5edb8a559beebcb64833177a893b49fb8eb9bfd2e650155a207c7ba7" nocase ascii wide
                        $string20_IPPrintC2_offensive_tool_keyword = "6ff59387bfda905c88b75b8f345bca0fd9ea0ab327da28572a4e60c8bf4e1c4d" nocase ascii wide
                        $string21_IPPrintC2_offensive_tool_keyword = "826c1daf512bcd2152b6328fc55b1ed403ed41fd1a6fc1afa6e35f34e4b9f8bc" nocase ascii wide
                        $string22_IPPrintC2_offensive_tool_keyword = /Add\-Printer\s\-Name\s\\"http\:\/\/\$server\/\$printername\\"\s\-PortName\s\\"http\:\/\/\$server\/printers\/\$printername\/\.printer\\"/ nocase ascii wide
                        $string23_IPPrintC2_offensive_tool_keyword = /Add\-Printer\s\-Name\s\$PrinterName\s\-DriverName\s\\"Generic\s\/\sText\sOnly\\"\s.{0,100}\s\-PortName/ nocase ascii wide
                        $string24_IPPrintC2_offensive_tool_keyword = /Add\-PrinterPort\s\$C2output/ nocase ascii wide
                        $string25_IPPrintC2_offensive_tool_keyword = /c\:\\temp\\c2\.pdf/ nocase ascii wide
                        $string26_IPPrintC2_offensive_tool_keyword = /C\:\\temp\\c2\.pdf/ nocase ascii wide
                        $string27_IPPrintC2_offensive_tool_keyword = "d222451147be2256c701679975cd45993377032f1d6afff27533bafda10c2afa" nocase ascii wide
                        $string28_IPPrintC2_offensive_tool_keyword = /DESKTOP\-PRINTINGFUN\\/ nocase ascii wide
                        $string29_IPPrintC2_offensive_tool_keyword = "Diverto/IPPrintC2" nocase ascii wide
                        $string30_IPPrintC2_offensive_tool_keyword = "Diverto/IPPrintC2" nocase ascii wide
                        $string31_IPPrintC2_offensive_tool_keyword = "fd52f1cd337f51b76463cc12d6d0c32108a324d6d72d57c852326053ca608495" nocase ascii wide
                        $string32_IPPrintC2_offensive_tool_keyword = "Invoke-DatatExfiltration" nocase ascii wide
                        $string33_IPPrintC2_offensive_tool_keyword = "Invoke-DatatExfiltration" nocase ascii wide
                        $string34_IPPrintC2_offensive_tool_keyword = "Invoke-FileC2Output" nocase ascii wide
                        $string35_IPPrintC2_offensive_tool_keyword = "Invoke-FileC2Output" nocase ascii wide
                        $string36_IPPrintC2_offensive_tool_keyword = "Invoke-ReadC2Output" nocase ascii wide
                        $string37_IPPrintC2_offensive_tool_keyword = "Invoke-ReadC2Output" nocase ascii wide
                        $string38_IPPrintC2_offensive_tool_keyword = /IPPrintC2\.ps1/ nocase ascii wide
                        $string39_IPPrintC2_offensive_tool_keyword = /IPPrintC2\-main\.zip/ nocase ascii wide
                        $string40_IPPrintC2_offensive_tool_keyword = /ls\s\-r\s\$ExfilDocname/ nocase ascii wide
                        $string41_IPPrintC2_offensive_tool_keyword = /New\-Item\s\$C2Output\s/ nocase ascii wide
                        $string42_IPPrintC2_offensive_tool_keyword = /New\-ScheduledTaskTrigger\s\-AtLogOn\s\-User\s\$env\:username\;Register\-ScheduledTask\s\-TaskName\s\\"Microsoft\sXPS\\"/ nocase ascii wide
                        $string43_IPPrintC2_offensive_tool_keyword = /powershell\s\-enc\s\(\(Get\-PrintJob\sXPS\)\.documentname\s\-join/ nocase ascii wide
                        $string44_IPPrintC2_offensive_tool_keyword = /powershell\s\-w\shidden\s\-NoExit\s\-c\s\{start\-job\s\-s\s\{while\(\$TRUE\)\{powershell\s\-EnC\s\(\(Get\-PrintJob\sXPS\)\.documentname\s\-join\s\'\'\)\;sleep\s60\}/ nocase ascii wide
                        $string45_IPPrintC2_offensive_tool_keyword = "Where do you want to store PDF C2 output " nocase ascii wide
                        $string46_IPPrintC2_offensive_tool_keyword = "Write-Host -ForegroundColor Yellow \"IPPrint C2 Server\"" nocase ascii wide
                        $string47_IPPrintC2_offensive_tool_keyword = "WwBzAGMAcgBpAHAAdABiAGwAbwBjAGsAXQAkAHgAPQB7AHcAaABvAGEAbQBpACAALwBhAGwAbAA7AGgAbwBzAHQAbgBhAG0AZQB9ADsAJAB4AC4AaQBuAHYAbwBrAGUAKAApAA" nocase ascii wide
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