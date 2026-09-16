rule rule_peeping_tom_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'peeping-tom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "peeping-tom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_peeping_tom_offensive_tool_keyword = /\/peeping\-client\.exe/ nocase ascii wide
                        $string2_peeping_tom_offensive_tool_keyword = /\/peeping\-tom\.app/ nocase ascii wide
                        $string3_peeping_tom_offensive_tool_keyword = /\/peeping\-tom\.exe/ nocase ascii wide
                        $string4_peeping_tom_offensive_tool_keyword = /\/peeping\-tom\.git/ nocase ascii wide
                        $string5_peeping_tom_offensive_tool_keyword = /\[\!\]\sPlease\ssave\sthis\skey\sas\sit\swill\sbe\srequired\sto\sdecrypt\sthe\skeylogs\sfrom\sthe\starget\!/ nocase ascii wide
                        $string6_peeping_tom_offensive_tool_keyword = /\[\+\]\sKeylog\srecieved\,\sdata\swritten\sto\skeylog\.txt\!/ nocase ascii wide
                        $string7_peeping_tom_offensive_tool_keyword = /\[Ngrok\sTunnel\sURL/ nocase ascii wide
                        $string8_peeping_tom_offensive_tool_keyword = /\\peeping\-client\.exe/ nocase ascii wide
                        $string9_peeping_tom_offensive_tool_keyword = /\\peeping\-tom\.exe/ nocase ascii wide
                        $string10_peeping_tom_offensive_tool_keyword = /\\peeping\-tom\-main/ nocase ascii wide
                        $string11_peeping_tom_offensive_tool_keyword = /\\toms\-server\\keylog\.txt/ nocase ascii wide
                        $string12_peeping_tom_offensive_tool_keyword = "63ec96c5-075f-4f22-92ec-cf28a2f70737" nocase ascii wide
                        $string13_peeping_tom_offensive_tool_keyword = "71bda8ea-08bc-4ab1-9b40-614b167beb64" nocase ascii wide
                        $string14_peeping_tom_offensive_tool_keyword = "8d352347e622b8ff6babf1a119266f59c1b14a48cebc4cb2cf84c00edd276fe3" nocase ascii wide
                        $string15_peeping_tom_offensive_tool_keyword = /abdullahansari1618\@outlook\.com/ nocase ascii wide
                        $string16_peeping_tom_offensive_tool_keyword = /API\:\:installHook\(\)\s\-\sWindows\skeyboard\shook\scould\snot\sbe\sinstalled\!/ nocase ascii wide
                        $string17_peeping_tom_offensive_tool_keyword = /Exfiltrate\:\:exfilLogs\(\)/ nocase ascii wide
                        $string18_peeping_tom_offensive_tool_keyword = "fbe18d97dcbd4ee2b6d3d9457142595613cb86a3f59fc7a54f52731925e5026e" nocase ascii wide
                        $string19_peeping_tom_offensive_tool_keyword = "Nothing was logged into the temp workingKeyLog!" nocase ascii wide
                        $string20_peeping_tom_offensive_tool_keyword = "shehzade/peeping-tom" nocase ascii wide
                        $string21_peeping_tom_offensive_tool_keyword = "Windows keyboard hook installed & log exfiltration timer started" nocase ascii wide
                        $string22_peeping_tom_offensive_tool_keyword = "workingKeyLog has been pushed to key log file!" nocase ascii wide
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