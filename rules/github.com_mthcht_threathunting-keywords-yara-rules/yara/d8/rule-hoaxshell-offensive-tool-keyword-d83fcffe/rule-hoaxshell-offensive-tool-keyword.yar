rule rule_hoaxshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hoaxshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hoaxshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hoaxshell_offensive_tool_keyword = /\s\=\s\[H\,O\,A\,X\,S\,H\,E\,L\,L\]/ nocase ascii wide
                        $string2_hoaxshell_offensive_tool_keyword = /\#\sAuthor\:\sPanagiotis\sChartas\s\(t3l3machus\)/ nocase ascii wide
                        $string3_hoaxshell_offensive_tool_keyword = /\.\/hoaxshell/
                        $string4_hoaxshell_offensive_tool_keyword = /\.py.{0,1000}\s\-\-localtunnel\s/ nocase ascii wide
                        $string5_hoaxshell_offensive_tool_keyword = /\.py.{0,1000}\s\-\-ngrok\s/ nocase ascii wide
                        $string6_hoaxshell_offensive_tool_keyword = /\/hoaxshell\.git/ nocase ascii wide
                        $string7_hoaxshell_offensive_tool_keyword = /\/http_payload\.ps1/ nocase ascii wide
                        $string8_hoaxshell_offensive_tool_keyword = /\/https_payload\.ps1/ nocase ascii wide
                        $string9_hoaxshell_offensive_tool_keyword = /\\hack\.ps1/ nocase ascii wide
                        $string10_hoaxshell_offensive_tool_keyword = "169158f7ab05b90fd880b4921decbbe9ff0b13d04592b4711cdcb07216f2d02a" nocase ascii wide
                        $string11_hoaxshell_offensive_tool_keyword = "409faf186d5c7ab9c289f8942614c716baed7107b57003f96d76f717bc197df4" nocase ascii wide
                        $string12_hoaxshell_offensive_tool_keyword = "5721ff8bccba2fec3918c3464b519d9b02b69f0cc69639eaa8964174d4cc6e36" nocase ascii wide
                        $string13_hoaxshell_offensive_tool_keyword = "5ce31dbbcce69be63eaddd6759ea115162e96500f9ee185b106eb47c5c1417ce" nocase ascii wide
                        $string14_hoaxshell_offensive_tool_keyword = "6d96904c0085f49b27a47e4d75542fe8d28b6de9431038d72fdfdb2f51e43171" nocase ascii wide
                        $string15_hoaxshell_offensive_tool_keyword = "80a9715cb597950d540961b82e1f6793af205d9de2de5e61e6b6e53fc45845b4" nocase ascii wide
                        $string16_hoaxshell_offensive_tool_keyword = "8c484c384d66dd2821b9f1d4f963ae897fbf539b2ab495f3e93344635eb76f18" nocase ascii wide
                        $string17_hoaxshell_offensive_tool_keyword = "9915aa1e343c454c31a1011d51fa3f3410a54cc70256d232d2b7a00bd1bd5583" nocase ascii wide
                        $string18_hoaxshell_offensive_tool_keyword = "9a0da3eeb072abdcdce6774d9eb431a2be86b03c3a82e34c0cf464f8150c4e2e" nocase ascii wide
                        $string19_hoaxshell_offensive_tool_keyword = "bac188a072ffe2acbdd2d33035c3747b3febad807f5db13caa7b15bcb5bff415" nocase ascii wide
                        $string20_hoaxshell_offensive_tool_keyword = "def46f338013e516bbe3823ab661abb80e80e1388f2b57c3aa9dedee7f4735be" nocase ascii wide
                        $string21_hoaxshell_offensive_tool_keyword = "e277468009b97989146089c83231fa03247555b6cc2979b68d549a0d0e8ea0e1" nocase ascii wide
                        $string22_hoaxshell_offensive_tool_keyword = /Hoaxshell\.exe/ nocase ascii wide
                        $string23_hoaxshell_offensive_tool_keyword = /hoaxshell\.py/ nocase ascii wide
                        $string24_hoaxshell_offensive_tool_keyword = /hoaxshell\-listener\.py/ nocase ascii wide
                        $string25_hoaxshell_offensive_tool_keyword = /https_payload_localtunnel\.ps1/ nocase ascii wide
                        $string26_hoaxshell_offensive_tool_keyword = /https_payload_localtunnel_outfile\.ps1/ nocase ascii wide
                        $string27_hoaxshell_offensive_tool_keyword = /https_payload_ngrok\.ps1/ nocase ascii wide
                        $string28_hoaxshell_offensive_tool_keyword = /https_payload_ngrok_outfile\.ps1/ nocase ascii wide
                        $string29_hoaxshell_offensive_tool_keyword = /https_payload_trusted\.ps1/ nocase ascii wide
                        $string30_hoaxshell_offensive_tool_keyword = "t3l3machus/hoaxshell" nocase ascii wide

    condition:
        any of them
}