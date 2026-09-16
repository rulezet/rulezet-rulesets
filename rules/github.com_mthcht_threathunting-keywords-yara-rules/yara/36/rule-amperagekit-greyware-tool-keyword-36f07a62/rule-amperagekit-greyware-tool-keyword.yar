rule rule_AmperageKit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AmperageKit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmperageKit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AmperageKit_greyware_tool_keyword = /\/Amperage\.exe/ nocase ascii wide
                        $string2_AmperageKit_greyware_tool_keyword = /\/AmperageKit\.git/ nocase ascii wide
                        $string3_AmperageKit_greyware_tool_keyword = "/AmperageKit/releases/" nocase ascii wide
                        $string4_AmperageKit_greyware_tool_keyword = /\\Amperage\.exe/ nocase ascii wide
                        $string5_AmperageKit_greyware_tool_keyword = /\\Amperage\\Program\.cs/ nocase ascii wide
                        $string6_AmperageKit_greyware_tool_keyword = /\\Amperage_v2024\.5\.31_arm64\.zip/ nocase ascii wide
                        $string7_AmperageKit_greyware_tool_keyword = /\\Amperage_v2024\.6\.1_arm64\.zip/ nocase ascii wide
                        $string8_AmperageKit_greyware_tool_keyword = /\\AmperageAIXSysRemove/ nocase ascii wide
                        $string9_AmperageKit_greyware_tool_keyword = /\\AmperageHwReqDetour/ nocase ascii wide
                        $string10_AmperageKit_greyware_tool_keyword = /\\AmperageKit\.sln/ nocase ascii wide
                        $string11_AmperageKit_greyware_tool_keyword = /\\ProgramData\\Amperage/ nocase ascii wide
                        $string12_AmperageKit_greyware_tool_keyword = "327F3F26-182F-4E58-ABEA-A0CEDBCA0FCD" nocase ascii wide
                        $string13_AmperageKit_greyware_tool_keyword = "3bdf7c5f0c87c94b461668137a3e7cbf757d59dafc7a063362c34d17f2f33e61" nocase ascii wide
                        $string14_AmperageKit_greyware_tool_keyword = "7334543f2f3555690c9a4995cf1d8e83beb9fa45e6aa147c49114a4ef89670b8" nocase ascii wide
                        $string15_AmperageKit_greyware_tool_keyword = "75dce532b65a7c7644a626196a8af9d8370e163e802847505fb033a6290fb4a5" nocase ascii wide
                        $string16_AmperageKit_greyware_tool_keyword = "7931404e96b6aff52bc81a852f1f545f0cd07712d648099ec0618f4e66a1807f" nocase ascii wide
                        $string17_AmperageKit_greyware_tool_keyword = "80C7245C-B926-4CEB-BA5B-5353736137A8" nocase ascii wide
                        $string18_AmperageKit_greyware_tool_keyword = "8e454334de0de74a6e53ee1d26e24cd2b0f41427922d9e92e6d49cf5db942a3c" nocase ascii wide
                        $string19_AmperageKit_greyware_tool_keyword = "A3454AF1-12AF-4952-B26D-FF0930DB779E" nocase ascii wide
                        $string20_AmperageKit_greyware_tool_keyword = "Amperage - Recall setup tool for unsupported hardware" nocase ascii wide
                        $string21_AmperageKit_greyware_tool_keyword = "cd1c54a8510c1e09d55868e12872aa54f9dc9ade95d70f08a173d29f6d676fde" nocase ascii wide
                        $string22_AmperageKit_greyware_tool_keyword = "d84efd06178700a83d135862d6c7419dce2e12df92c78850dc7cc5b1da482abd" nocase ascii wide
                        $string23_AmperageKit_greyware_tool_keyword = "ed0375afd9b26b18fd9b72bbb416dbf8bec289bf135facf4b7ba5cd2b1d86208" nocase ascii wide
                        $string24_AmperageKit_greyware_tool_keyword = "Removing AIX package from all standard users" nocase ascii wide
                        $string25_AmperageKit_greyware_tool_keyword = "thebookisclosed/AmperageKit" nocase ascii wide

    condition:
        any of them
}