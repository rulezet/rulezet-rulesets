rule dnskire
{
    meta:
        description = "Detection patterns for the tool 'dnskire' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnskire"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " dnskire:dnskire " nocase ascii wide
                        $string2 = /\smkzoneslices\.sh/ nocase ascii wide
                        $string3 = " -R dnskire:bind " nocase ascii wide
                        $string4 = /\/certs\/dnsKIRE\.local\.crt/
                        $string5 = /\/certs\/dnsKIRE\.local\.key/
                        $string6 = /\/CN\=dnsKIRE\.local/
                        $string7 = /\/db\/dnskire\.db/
                        $string8 = /\/dnskire\.git/ nocase ascii wide
                        $string9 = /\/dnskire\.js/ nocase ascii wide
                        $string10 = /\/dnskire\.log/
                        $string11 = /\/dnskire\/\.ssh\//
                        $string12 = /\/mkzoneslices\.sh/ nocase ascii wide
                        $string13 = /\\dnskire\.js/ nocase ascii wide
                        $string14 = "0fd74299abc6f3a23b609351d6fc3e7c524b2e4652a4691ec11c9c6ec1ab48d2" nocase ascii wide
                        $string15 = "0xtosh/dnskire" nocase ascii wide
                        $string16 = "14cacb095c7f6d3347fe36b6576fde73047897330bae662fc29ef9f8169e0136" nocase ascii wide
                        $string17 = "7acb019f05541c2f8549a9d7250b5bb2c6cad5a795b73e874fbc0865fdb4719b" nocase ascii wide
                        $string18 = "d685191b55fec64ce5fa0ced8bff472aa1a297d0e77354da28f34d0f67a4dec4" nocase ascii wide
                        $string19 = "DNS retrieval done - converting to file" nocase ascii wide
                        $string20 = /dnskire\sALL\=\(ALL\:ALL\)\sNOPASSWD\:\sALL/
                        $string21 = /dnskire\smay.{0,1000}\(ALL\s\:\sALL\)\sNOPASSWD\:\sALL/
                        $string22 = /dnsKIRE\sstarted\!\\n/ nocase ascii wide
                        $string23 = "dnskire-install" nocase ascii wide
                        $string24 = /Get\-Content\s\-path\s\$dnshexfile\s/ nocase ascii wide
                        $string25 = /https\:\/\/1\.3\.3\.7\:8081/ nocase ascii wide
                        $string26 = "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwppbXBvcnQgZG5zLnJlc29sdmVyCmltcG9ydCBvcwppbXBvcnQgcmFuZG9tCmltcG9ydCB0aW1lCgo=" nocase ascii wide
                        $string27 = "mkdir dnskire/" nocase ascii wide
                        $string28 = /node\sdnskire\.js/ nocase ascii wide
                        $string29 = "screen -S dnskire -" nocase ascii wide
                        $string30 = /scripts\/zoneadm\.sh/ nocase ascii wide
                        $string31 = "sudo -l -U dnskire"
                        $string32 = /totally\-not\-meterpreter\.7z/ nocase ascii wide

    condition:
        any of them
}