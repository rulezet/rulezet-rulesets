rule rule_ADCSCoercePotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADCSCoercePotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSCoercePotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADCSCoercePotato_offensive_tool_keyword = /\.asp\s\-\-adcs\s\-\-template\sMachine\s\-smb2support/ nocase ascii wide
                        $string2_ADCSCoercePotato_offensive_tool_keyword = /\/ADCSCoercePotato\.git/ nocase ascii wide
                        $string3_ADCSCoercePotato_offensive_tool_keyword = "/ADCSCoercePotato/" nocase ascii wide
                        $string4_ADCSCoercePotato_offensive_tool_keyword = /\[\!\]\sCouldn\'t\scommunicate\swith\sthe\sfake\sRPC\sServer/ nocase ascii wide
                        $string5_ADCSCoercePotato_offensive_tool_keyword = /\[\+\]\sGot\sNTLM\stype\s3\sAUTH\smessage\sfrom\s.{0,1000}\swith\shostname\s/ nocase ascii wide
                        $string6_ADCSCoercePotato_offensive_tool_keyword = /\\ADCSCoercePotato\\/ nocase ascii wide
                        $string7_ADCSCoercePotato_offensive_tool_keyword = /\\MSFRottenPotato\.h/ nocase ascii wide
                        $string8_ADCSCoercePotato_offensive_tool_keyword = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase ascii wide
                        $string9_ADCSCoercePotato_offensive_tool_keyword = /ADCSCoercePotato\.cpp/ nocase ascii wide
                        $string10_ADCSCoercePotato_offensive_tool_keyword = /ADCSCoercePotato\.exe/ nocase ascii wide
                        $string11_ADCSCoercePotato_offensive_tool_keyword = /ADCSCoercePotato\.sln/ nocase ascii wide
                        $string12_ADCSCoercePotato_offensive_tool_keyword = /ADCSCoercePotato\.vcxproj/ nocase ascii wide
                        $string13_ADCSCoercePotato_offensive_tool_keyword = /ADCSCoercePotato\\n\-\s\@decoder_it\s2024\\/ nocase ascii wide
                        $string14_ADCSCoercePotato_offensive_tool_keyword = "decoder-it/ADCSCoercePotato" nocase ascii wide
                        $string15_ADCSCoercePotato_offensive_tool_keyword = /include\s\\"MSFRottenPotato\.h\\"/ nocase ascii wide
                        $string16_ADCSCoercePotato_offensive_tool_keyword = "int PotatoAPI::findNTLMBytes" nocase ascii wide

    condition:
        any of them
}