rule rule_UnmanagedPowerShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UnmanagedPowerShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnmanagedPowerShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UnmanagedPowerShell_offensive_tool_keyword = /\/UnmanagedPowerShell\.git/ nocase ascii wide
                        $string2_UnmanagedPowerShell_offensive_tool_keyword = /\\PowerShellRunnerDll\.h/ nocase ascii wide
                        $string3_UnmanagedPowerShell_offensive_tool_keyword = /\\UnmanagedPowerShell\.cpp/ nocase ascii wide
                        $string4_UnmanagedPowerShell_offensive_tool_keyword = /\\UnmanagedPowerShell\.exe/ nocase ascii wide
                        $string5_UnmanagedPowerShell_offensive_tool_keyword = /\\UnmanagedPowerShell\.sln/ nocase ascii wide
                        $string6_UnmanagedPowerShell_offensive_tool_keyword = /\\UnmanagedPowerShell\.vcxproj/ nocase ascii wide
                        $string7_UnmanagedPowerShell_offensive_tool_keyword = "5A9955E4-62B7-419D-AB73-01A6D7DD27FC" nocase ascii wide
                        $string8_UnmanagedPowerShell_offensive_tool_keyword = "692110b2f60de3d52ac15e84be38fab5f9a16249b2bb0011af047b174efceeda" nocase ascii wide
                        $string9_UnmanagedPowerShell_offensive_tool_keyword = "6EB55FE6-C11C-453B-8B32-22B689B6B3E2" nocase ascii wide
                        $string10_UnmanagedPowerShell_offensive_tool_keyword = "leechristensen/UnmanagedPowerShell" nocase ascii wide

    condition:
        any of them
}