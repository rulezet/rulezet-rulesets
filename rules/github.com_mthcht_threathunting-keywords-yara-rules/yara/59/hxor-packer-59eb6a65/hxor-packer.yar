rule hXOR_Packer
{
    meta:
        description = "Detection patterns for the tool 'hXOR-Packer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hXOR-Packer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/hXOR\.exe/ nocase ascii wide
                        $string2 = /\/hXOR\-Packer\.git/ nocase ascii wide
                        $string3 = /\\antiDefense\.cpp/ nocase ascii wide
                        $string4 = /\\hXOR\.exe/ nocase ascii wide
                        $string5 = /\\hXOR\-Packer\sv0\.1\\/ nocase ascii wide
                        $string6 = /\\hXOR\-Packer\\/ nocase ascii wide
                        $string7 = /\\unpackerLoadEXE\.exe/ nocase ascii wide
                        $string8 = "akuafif/hXOR-Packer" nocase ascii wide
                        $string9 = /hXOR\-Packer\.v0\.1\.zip/ nocase ascii wide
                        $string10 = "hXOR-Packer-main" nocase ascii wide
                        $string11 = /packer\.exe\s.{0,1000}\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string12 = "Sandboxie detected!!!" nocase ascii wide
                        $string13 = /Scanning\sfor\sSandboxie\?/ nocase ascii wide
                        $string14 = /Unpacking\sSuccessful\!\\n\\nExecuting\sfrom\sMemory\s\>\>\>\>\s/ nocase ascii wide
                        $string15 = "VMware detected!!!" nocase ascii wide

    condition:
        any of them
}