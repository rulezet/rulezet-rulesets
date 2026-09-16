rule rule_physmem2profit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'physmem2profit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "physmem2profit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_physmem2profit_offensive_tool_keyword = /\sphysmem2minidump\.py/ nocase ascii wide
                        $string2_physmem2profit_offensive_tool_keyword = /\/label\-date\-lsass\.dmp/ nocase ascii wide
                        $string3_physmem2profit_offensive_tool_keyword = /\/physmem2minidump\.py/ nocase ascii wide
                        $string4_physmem2profit_offensive_tool_keyword = /\/physmem2profit\.git/ nocase ascii wide
                        $string5_physmem2profit_offensive_tool_keyword = /\\physmem2minidump\.py/ nocase ascii wide
                        $string6_physmem2profit_offensive_tool_keyword = /\\physmem2profit\-master/ nocase ascii wide
                        $string7_physmem2profit_offensive_tool_keyword = ">physmem2profit<" nocase ascii wide
                        $string8_physmem2profit_offensive_tool_keyword = "23ecca2af6db4c425ab534b9a738f7ec152c7fcf3c250f3ce9d7f57e6259eac9" nocase ascii wide
                        $string9_physmem2profit_offensive_tool_keyword = "814708C9-2320-42D2-A45F-31E42DA06A94" nocase ascii wide
                        $string10_physmem2profit_offensive_tool_keyword = "cc24850f03dccbd8ee3a372b06b2a77a95e5314bb68d2483b1814935978b7003" nocase ascii wide
                        $string11_physmem2profit_offensive_tool_keyword = "MimikatzStream should be at offset " nocase ascii wide
                        $string12_physmem2profit_offensive_tool_keyword = /output.{0,1000}\-lsass\.dmp/ nocase ascii wide
                        $string13_physmem2profit_offensive_tool_keyword = /physmem2profit\.exe/ nocase ascii wide
                        $string14_physmem2profit_offensive_tool_keyword = /Physmem2profit\.sln/ nocase ascii wide
                        $string15_physmem2profit_offensive_tool_keyword = /physmem2profit\-public\.zip/ nocase ascii wide
                        $string16_physmem2profit_offensive_tool_keyword = "source physmem2profit" nocase ascii wide
                        $string17_physmem2profit_offensive_tool_keyword = "WithSecureLabs/physmem2profit" nocase ascii wide

    condition:
        any of them
}