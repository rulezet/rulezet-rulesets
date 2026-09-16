rule rule_BlockEtw_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BlockEtw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockEtw"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BlockEtw_offensive_tool_keyword = /\/blocketw\.bin/ nocase ascii wide
                        $string2_BlockEtw_offensive_tool_keyword = /\/blocketw\.exe/ nocase ascii wide
                        $string3_BlockEtw_offensive_tool_keyword = /\/BlockEtw\.git/ nocase ascii wide
                        $string4_BlockEtw_offensive_tool_keyword = "/BlockEtw/tarball/" nocase ascii wide
                        $string5_BlockEtw_offensive_tool_keyword = "/BlockEtw/zipball/" nocase ascii wide
                        $string6_BlockEtw_offensive_tool_keyword = /\/opt\/shellcode\/blocketw\.bin/ nocase ascii wide
                        $string7_BlockEtw_offensive_tool_keyword = /\\blocketw\.bin/ nocase ascii wide
                        $string8_BlockEtw_offensive_tool_keyword = /\\blocketw\.csproj/ nocase ascii wide
                        $string9_BlockEtw_offensive_tool_keyword = /\\blocketw\.exe/ nocase ascii wide
                        $string10_BlockEtw_offensive_tool_keyword = /\\blocketw\.pdb/ nocase ascii wide
                        $string11_BlockEtw_offensive_tool_keyword = /\\blocketw\.sln/ nocase ascii wide
                        $string12_BlockEtw_offensive_tool_keyword = /\\BlockEtw\-master/ nocase ascii wide
                        $string13_BlockEtw_offensive_tool_keyword = /\\Derek\.Admin\.STANNCENTER\\Source\\Repos\\/ nocase ascii wide
                        $string14_BlockEtw_offensive_tool_keyword = ">blocketw<" nocase ascii wide
                        $string15_BlockEtw_offensive_tool_keyword = "0e313d439e080ae59303f87afe484717dab784c8df5f83dcd2745b51194582a8" nocase ascii wide
                        $string16_BlockEtw_offensive_tool_keyword = "0e313d439e080ae59303f87afe484717dab784c8df5f83dcd2745b51194582a8" nocase ascii wide
                        $string17_BlockEtw_offensive_tool_keyword = "55d70f97e0f0c76b7a6ed08178f83ccd5505e8c62213d1fdf5221bc60cf3ffe0" nocase ascii wide
                        $string18_BlockEtw_offensive_tool_keyword = "8904000180688b0ba69b2bc6647fc42c34ed9fce15ed7687d53958f9f9ac6357" nocase ascii wide
                        $string19_BlockEtw_offensive_tool_keyword = "a5034ebb8d6c31c71947c4f85a505f66fd1aadc71cecedd96f1bd02b3e471f62" nocase ascii wide
                        $string20_BlockEtw_offensive_tool_keyword = "a5034ebb8d6c31c71947c4f85a505f66fd1aadc71cecedd96f1bd02b3e471f62" nocase ascii wide
                        $string21_BlockEtw_offensive_tool_keyword = "cb287d756b38831a47d5cd86e5b332be4997d89fa275de5a99883ec151b4bbdc" nocase ascii wide
                        $string22_BlockEtw_offensive_tool_keyword = "cdbf8f32f74fdb65c2a34bfbf7208e24f0c9cc058d76fed96289964fcff50e2a" nocase ascii wide
                        $string23_BlockEtw_offensive_tool_keyword = "DAEDF7B3-8262-4892-ADC4-425DD5F85BCA" nocase ascii wide
                        $string24_BlockEtw_offensive_tool_keyword = "f94889e1ba519e9e4e4e7bbee99f29ee46ab218b45d3a1b49549deba41f083ff" nocase ascii wide
                        $string25_BlockEtw_offensive_tool_keyword = "Soledge/BlockEtw" nocase ascii wide

    condition:
        any of them
}