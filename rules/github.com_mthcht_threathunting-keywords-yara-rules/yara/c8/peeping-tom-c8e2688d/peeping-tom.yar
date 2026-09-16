rule peeping_tom
{
    meta:
        description = "Detection patterns for the tool 'peeping-tom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "peeping-tom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/peeping\-client\.exe/ nocase ascii wide
                        $string2 = /\/peeping\-tom\.app/ nocase ascii wide
                        $string3 = /\/peeping\-tom\.exe/ nocase ascii wide
                        $string4 = /\/peeping\-tom\.git/ nocase ascii wide
                        $string5 = /\[\!\]\sPlease\ssave\sthis\skey\sas\sit\swill\sbe\srequired\sto\sdecrypt\sthe\skeylogs\sfrom\sthe\starget\!/ nocase ascii wide
                        $string6 = /\[\+\]\sKeylog\srecieved\,\sdata\swritten\sto\skeylog\.txt\!/ nocase ascii wide
                        $string7 = /\[Ngrok\sTunnel\sURL/ nocase ascii wide
                        $string8 = /\\peeping\-client\.exe/ nocase ascii wide
                        $string9 = /\\peeping\-tom\.exe/ nocase ascii wide
                        $string10 = /\\peeping\-tom\-main/ nocase ascii wide
                        $string11 = /\\toms\-server\\keylog\.txt/ nocase ascii wide
                        $string12 = "63ec96c5-075f-4f22-92ec-cf28a2f70737" nocase ascii wide
                        $string13 = "71bda8ea-08bc-4ab1-9b40-614b167beb64" nocase ascii wide
                        $string14 = "8d352347e622b8ff6babf1a119266f59c1b14a48cebc4cb2cf84c00edd276fe3" nocase ascii wide
                        $string15 = /abdullahansari1618\@outlook\.com/ nocase ascii wide
                        $string16 = /API\:\:installHook\(\)\s\-\sWindows\skeyboard\shook\scould\snot\sbe\sinstalled\!/ nocase ascii wide
                        $string17 = /Exfiltrate\:\:exfilLogs\(\)/ nocase ascii wide
                        $string18 = "fbe18d97dcbd4ee2b6d3d9457142595613cb86a3f59fc7a54f52731925e5026e" nocase ascii wide
                        $string19 = "Nothing was logged into the temp workingKeyLog!" nocase ascii wide
                        $string20 = "shehzade/peeping-tom" nocase ascii wide
                        $string21 = "Windows keyboard hook installed & log exfiltration timer started" nocase ascii wide
                        $string22 = "workingKeyLog has been pushed to key log file!" nocase ascii wide
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