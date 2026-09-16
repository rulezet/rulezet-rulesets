rule rule_S4UTomato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'S4UTomato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S4UTomato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_S4UTomato_offensive_tool_keyword = /\s\/s4uproxytarget\:.{0,1000}\s\/s4utransitiedservices\:/ nocase ascii wide
                        $string2_S4UTomato_offensive_tool_keyword = /\sYou\sneed\sto\shave\san\selevated\scontext\sto\sdump\sother\susers\'\sKerberos\stickets\s\:\(/ nocase ascii wide
                        $string3_S4UTomato_offensive_tool_keyword = "\"UACBypassedService\"" nocase ascii wide
                        $string4_S4UTomato_offensive_tool_keyword = /\(msds\-supportedencryptiontypes\=0\)\(msds\-supportedencryptiontypes\:1\.2\.840\.113556\.1\.4\.803\:\=4\)\)\)/ nocase ascii wide
                        $string5_S4UTomato_offensive_tool_keyword = /\.exe\skrbscm\s\-c\s.{0,1000}cmd\.exe/ nocase ascii wide
                        $string6_S4UTomato_offensive_tool_keyword = /\.exe\srbcd\s\-m\s.{0,1000}\s\-p\s.{0,1000}\s\-c\s.{0,1000}cmd\.exe/ nocase ascii wide
                        $string7_S4UTomato_offensive_tool_keyword = /\.exe\sshadowcred\s\-c\s.{0,1000}\s\-f/ nocase ascii wide
                        $string8_S4UTomato_offensive_tool_keyword = /\/ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
                        $string9_S4UTomato_offensive_tool_keyword = /\/MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string10_S4UTomato_offensive_tool_keyword = /\/S4UTomato\.git/ nocase ascii wide
                        $string11_S4UTomato_offensive_tool_keyword = /\[\+\]\sAS\-REQ\sw\/o\spreauth\ssuccessful\!/ nocase ascii wide
                        $string12_S4UTomato_offensive_tool_keyword = /\[\+\]\scross\srealm\sS4U2Self\ssuccess\!/ nocase ascii wide
                        $string13_S4UTomato_offensive_tool_keyword = /\[\+\]\sS4U2proxy\ssuccess\!/ nocase ascii wide
                        $string14_S4UTomato_offensive_tool_keyword = /\[\+\]\sS4U2self\ssuccess\!/ nocase ascii wide
                        $string15_S4UTomato_offensive_tool_keyword = /\\ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
                        $string16_S4UTomato_offensive_tool_keyword = /\\MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string17_S4UTomato_offensive_tool_keyword = /\\S4U\.Exe/ nocase ascii wide
                        $string18_S4UTomato_offensive_tool_keyword = /\\S4UTomato\\/ nocase ascii wide
                        $string19_S4UTomato_offensive_tool_keyword = /\\ShadowCredentials\.cs/ nocase ascii wide
                        $string20_S4UTomato_offensive_tool_keyword = /\\UACBypassedService/ nocase ascii wide
                        $string21_S4UTomato_offensive_tool_keyword = /\]\sRetrieving\sthe\sS4U2Self\sreferral\sfrom\s/ nocase ascii wide
                        $string22_S4UTomato_offensive_tool_keyword = /\]\sRoasted\shashes\swritten\sto\s\:\s/ nocase ascii wide
                        $string23_S4UTomato_offensive_tool_keyword = /\]\sSending\sS4U2proxy\srequest\s/ nocase ascii wide
                        $string24_S4UTomato_offensive_tool_keyword = ">UACBypassedService<" nocase ascii wide
                        $string25_S4UTomato_offensive_tool_keyword = "0cf16d4d70941be216c787a44a7401c9c9547016952a2c699579d4e4bb9c8110" nocase ascii wide
                        $string26_S4UTomato_offensive_tool_keyword = "3c3a96d02e34589d314b230c417b122970e492282767211866c8ac042e8bd556" nocase ascii wide
                        $string27_S4UTomato_offensive_tool_keyword = "881D4D67-46DD-4F40-A813-C9D3C8BE0965" nocase ascii wide
                        $string28_S4UTomato_offensive_tool_keyword = "bc25b38d07d2dbc8c7d9491a0779dcfaf87ea69ce078900ed61d307f45da33c3" nocase ascii wide
                        $string29_S4UTomato_offensive_tool_keyword = /localS4U2Proxy\.tickets/ nocase ascii wide
                        $string30_S4UTomato_offensive_tool_keyword = "Run the krbscm method for SYSTEM shell" nocase ascii wide
                        $string31_S4UTomato_offensive_tool_keyword = /S4UTomato\s1\.0\.0\-beta/ nocase ascii wide
                        $string32_S4UTomato_offensive_tool_keyword = /S4UTomato\.csproj/ nocase ascii wide
                        $string33_S4UTomato_offensive_tool_keyword = /S4UTomato\.exe/ nocase ascii wide
                        $string34_S4UTomato_offensive_tool_keyword = /S4UTomato\.lib/ nocase ascii wide
                        $string35_S4UTomato_offensive_tool_keyword = /S4UTomato\.sln/ nocase ascii wide
                        $string36_S4UTomato_offensive_tool_keyword = "S4UTomato-master" nocase ascii wide
                        $string37_S4UTomato_offensive_tool_keyword = /ShadowCredentials\.Execute\(/ nocase ascii wide
                        $string38_S4UTomato_offensive_tool_keyword = /UserAgent\s\=\s\\"Rubeus\/1\.0\\"/ nocase ascii wide
                        $string39_S4UTomato_offensive_tool_keyword = "wh0amitz/S4UTomato" nocase ascii wide

    condition:
        any of them
}