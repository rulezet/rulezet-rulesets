rule IPPrintC2
{
    meta:
        description = "Detection patterns for the tool 'IPPrintC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IPPrintC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sIPPrintC2\.ps1/ nocase ascii wide
                        $string2 = "\"IPPrint C2 Server\"" nocase ascii wide
                        $string3 = /\$C2ExternalIP\s\=\s/ nocase ascii wide
                        $string4 = /\$C2ExternalIP/ nocase ascii wide
                        $string5 = /\$C2Output\@\$date\.pdf/ nocase ascii wide
                        $string6 = /\$EncodedCommandExfil/ nocase ascii wide
                        $string7 = /\$IPPrintC2\s\=\s/ nocase ascii wide
                        $string8 = /\$IPPrintC2/ nocase ascii wide
                        $string9 = /\$IPPrintC2\.DocumentName/ nocase ascii wide
                        $string10 = /\$IPPrintC2\.Print/ nocase ascii wide
                        $string11 = /\(Invoke\-WebRequest\s\-Uri\s\\"https\:\/\/ifconfig\.me\/ip\\"\)\.Content/ nocase ascii wide
                        $string12 = /\/IPPrintC2\.git/ nocase ascii wide
                        $string13 = /\/IPPrintC2\.git/ nocase ascii wide
                        $string14 = /\/IPPrintC2\.ps1/ nocase ascii wide
                        $string15 = /\[System\.Text\.Encoding\]\:\:Unicode\.GetBytes\(\\"\[scriptblock\].{0,1000}\$x\=\{\$CommandDoc\}\;.{0,1000}\$x\.Invoke\(\)/ nocase ascii wide
                        $string16 = /\\\\DESKTOP\-PRINTINGFUN/ nocase ascii wide
                        $string17 = /\\IPPrintC2\.ps1/ nocase ascii wide
                        $string18 = "49656d058f63398c98cff95a5bbe76a6911e003ddb7baea082a7e7752525d6a6" nocase ascii wide
                        $string19 = "4c02774a5edb8a559beebcb64833177a893b49fb8eb9bfd2e650155a207c7ba7" nocase ascii wide
                        $string20 = "6ff59387bfda905c88b75b8f345bca0fd9ea0ab327da28572a4e60c8bf4e1c4d" nocase ascii wide
                        $string21 = "826c1daf512bcd2152b6328fc55b1ed403ed41fd1a6fc1afa6e35f34e4b9f8bc" nocase ascii wide
                        $string22 = /Add\-Printer\s\-Name\s\\"http\:\/\/\$server\/\$printername\\"\s\-PortName\s\\"http\:\/\/\$server\/printers\/\$printername\/\.printer\\"/ nocase ascii wide
                        $string23 = /Add\-Printer\s\-Name\s\$PrinterName\s\-DriverName\s\\"Generic\s\/\sText\sOnly\\"\s.{0,1000}\s\-PortName/ nocase ascii wide
                        $string24 = /Add\-PrinterPort\s\$C2output/ nocase ascii wide
                        $string25 = /c\:\\temp\\c2\.pdf/ nocase ascii wide
                        $string26 = /C\:\\temp\\c2\.pdf/ nocase ascii wide
                        $string27 = "d222451147be2256c701679975cd45993377032f1d6afff27533bafda10c2afa" nocase ascii wide
                        $string28 = /DESKTOP\-PRINTINGFUN\\/ nocase ascii wide
                        $string29 = "Diverto/IPPrintC2" nocase ascii wide
                        $string30 = "Diverto/IPPrintC2" nocase ascii wide
                        $string31 = "fd52f1cd337f51b76463cc12d6d0c32108a324d6d72d57c852326053ca608495" nocase ascii wide
                        $string32 = "Invoke-DatatExfiltration" nocase ascii wide
                        $string33 = "Invoke-DatatExfiltration" nocase ascii wide
                        $string34 = "Invoke-FileC2Output" nocase ascii wide
                        $string35 = "Invoke-FileC2Output" nocase ascii wide
                        $string36 = "Invoke-ReadC2Output" nocase ascii wide
                        $string37 = "Invoke-ReadC2Output" nocase ascii wide
                        $string38 = /IPPrintC2\.ps1/ nocase ascii wide
                        $string39 = /IPPrintC2\-main\.zip/ nocase ascii wide
                        $string40 = /ls\s\-r\s\$ExfilDocname/ nocase ascii wide
                        $string41 = /New\-Item\s\$C2Output\s/ nocase ascii wide
                        $string42 = /New\-ScheduledTaskTrigger\s\-AtLogOn\s\-User\s\$env\:username\;Register\-ScheduledTask\s\-TaskName\s\\"Microsoft\sXPS\\"/ nocase ascii wide
                        $string43 = /powershell\s\-enc\s\(\(Get\-PrintJob\sXPS\)\.documentname\s\-join/ nocase ascii wide
                        $string44 = /powershell\s\-w\shidden\s\-NoExit\s\-c\s\{start\-job\s\-s\s\{while\(\$TRUE\)\{powershell\s\-EnC\s\(\(Get\-PrintJob\sXPS\)\.documentname\s\-join\s\'\'\)\;sleep\s60\}/ nocase ascii wide
                        $string45 = "Where do you want to store PDF C2 output " nocase ascii wide
                        $string46 = "Write-Host -ForegroundColor Yellow \"IPPrint C2 Server\"" nocase ascii wide
                        $string47 = "WwBzAGMAcgBpAHAAdABiAGwAbwBjAGsAXQAkAHgAPQB7AHcAaABvAGEAbQBpACAALwBhAGwAbAA7AGgAbwBzAHQAbgBhAG0AZQB9ADsAJAB4AC4AaQBuAHYAbwBrAGUAKAApAA" nocase ascii wide

    condition:
        any of them
}