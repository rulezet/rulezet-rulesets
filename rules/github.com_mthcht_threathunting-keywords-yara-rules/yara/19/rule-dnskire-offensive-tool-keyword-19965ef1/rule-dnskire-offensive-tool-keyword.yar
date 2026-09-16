rule rule_dnskire_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnskire' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnskire"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnskire_offensive_tool_keyword = " dnskire:dnskire " nocase ascii wide
                        $string2_dnskire_offensive_tool_keyword = /\smkzoneslices\.sh/ nocase ascii wide
                        $string3_dnskire_offensive_tool_keyword = " -R dnskire:bind " nocase ascii wide
                        $string4_dnskire_offensive_tool_keyword = /\/certs\/dnsKIRE\.local\.crt/
                        $string5_dnskire_offensive_tool_keyword = /\/certs\/dnsKIRE\.local\.key/
                        $string6_dnskire_offensive_tool_keyword = /\/CN\=dnsKIRE\.local/
                        $string7_dnskire_offensive_tool_keyword = /\/db\/dnskire\.db/
                        $string8_dnskire_offensive_tool_keyword = /\/dnskire\.git/ nocase ascii wide
                        $string9_dnskire_offensive_tool_keyword = /\/dnskire\.js/ nocase ascii wide
                        $string10_dnskire_offensive_tool_keyword = /\/dnskire\.log/
                        $string11_dnskire_offensive_tool_keyword = /\/dnskire\/\.ssh\//
                        $string12_dnskire_offensive_tool_keyword = /\/mkzoneslices\.sh/ nocase ascii wide
                        $string13_dnskire_offensive_tool_keyword = /\\dnskire\.js/ nocase ascii wide
                        $string14_dnskire_offensive_tool_keyword = "0fd74299abc6f3a23b609351d6fc3e7c524b2e4652a4691ec11c9c6ec1ab48d2" nocase ascii wide
                        $string15_dnskire_offensive_tool_keyword = "0xtosh/dnskire" nocase ascii wide
                        $string16_dnskire_offensive_tool_keyword = "14cacb095c7f6d3347fe36b6576fde73047897330bae662fc29ef9f8169e0136" nocase ascii wide
                        $string17_dnskire_offensive_tool_keyword = "7acb019f05541c2f8549a9d7250b5bb2c6cad5a795b73e874fbc0865fdb4719b" nocase ascii wide
                        $string18_dnskire_offensive_tool_keyword = "d685191b55fec64ce5fa0ced8bff472aa1a297d0e77354da28f34d0f67a4dec4" nocase ascii wide
                        $string19_dnskire_offensive_tool_keyword = "DNS retrieval done - converting to file" nocase ascii wide
                        $string20_dnskire_offensive_tool_keyword = /dnskire\sALL\=\(ALL\:ALL\)\sNOPASSWD\:\sALL/
                        $string21_dnskire_offensive_tool_keyword = /dnskire\smay.{0,100}\(ALL\s\:\sALL\)\sNOPASSWD\:\sALL/
                        $string22_dnskire_offensive_tool_keyword = /dnsKIRE\sstarted\!\\n/ nocase ascii wide
                        $string23_dnskire_offensive_tool_keyword = "dnskire-install" nocase ascii wide
                        $string24_dnskire_offensive_tool_keyword = /Get\-Content\s\-path\s\$dnshexfile\s/ nocase ascii wide
                        $string25_dnskire_offensive_tool_keyword = /https\:\/\/1\.3\.3\.7\:8081/ nocase ascii wide
                        $string26_dnskire_offensive_tool_keyword = "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwppbXBvcnQgZG5zLnJlc29sdmVyCmltcG9ydCBvcwppbXBvcnQgcmFuZG9tCmltcG9ydCB0aW1lCgo=" nocase ascii wide
                        $string27_dnskire_offensive_tool_keyword = "mkdir dnskire/" nocase ascii wide
                        $string28_dnskire_offensive_tool_keyword = /node\sdnskire\.js/ nocase ascii wide
                        $string29_dnskire_offensive_tool_keyword = "screen -S dnskire -" nocase ascii wide
                        $string30_dnskire_offensive_tool_keyword = /scripts\/zoneadm\.sh/ nocase ascii wide
                        $string31_dnskire_offensive_tool_keyword = "sudo -l -U dnskire"
                        $string32_dnskire_offensive_tool_keyword = /totally\-not\-meterpreter\.7z/ nocase ascii wide
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