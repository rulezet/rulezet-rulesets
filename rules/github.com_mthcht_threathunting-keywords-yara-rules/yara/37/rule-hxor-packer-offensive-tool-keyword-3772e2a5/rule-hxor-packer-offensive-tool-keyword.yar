rule rule_hXOR_Packer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hXOR-Packer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hXOR-Packer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hXOR_Packer_offensive_tool_keyword = /\/hXOR\.exe/ nocase ascii wide
                        $string2_hXOR_Packer_offensive_tool_keyword = /\/hXOR\-Packer\.git/ nocase ascii wide
                        $string3_hXOR_Packer_offensive_tool_keyword = /\\antiDefense\.cpp/ nocase ascii wide
                        $string4_hXOR_Packer_offensive_tool_keyword = /\\hXOR\.exe/ nocase ascii wide
                        $string5_hXOR_Packer_offensive_tool_keyword = /\\hXOR\-Packer\sv0\.1\\/ nocase ascii wide
                        $string6_hXOR_Packer_offensive_tool_keyword = /\\hXOR\-Packer\\/ nocase ascii wide
                        $string7_hXOR_Packer_offensive_tool_keyword = /\\unpackerLoadEXE\.exe/ nocase ascii wide
                        $string8_hXOR_Packer_offensive_tool_keyword = "akuafif/hXOR-Packer" nocase ascii wide
                        $string9_hXOR_Packer_offensive_tool_keyword = /hXOR\-Packer\.v0\.1\.zip/ nocase ascii wide
                        $string10_hXOR_Packer_offensive_tool_keyword = "hXOR-Packer-main" nocase ascii wide
                        $string11_hXOR_Packer_offensive_tool_keyword = /packer\.exe\s.{0,1000}\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string12_hXOR_Packer_offensive_tool_keyword = "Sandboxie detected!!!" nocase ascii wide
                        $string13_hXOR_Packer_offensive_tool_keyword = /Scanning\sfor\sSandboxie\?/ nocase ascii wide
                        $string14_hXOR_Packer_offensive_tool_keyword = /Unpacking\sSuccessful\!\\n\\nExecuting\sfrom\sMemory\s\>\>\>\>\s/ nocase ascii wide
                        $string15_hXOR_Packer_offensive_tool_keyword = "VMware detected!!!" nocase ascii wide

    condition:
        any of them
}