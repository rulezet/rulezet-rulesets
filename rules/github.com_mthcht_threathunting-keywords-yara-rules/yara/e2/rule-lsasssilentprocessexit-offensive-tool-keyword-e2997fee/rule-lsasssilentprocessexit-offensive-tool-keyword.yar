rule rule_LsassSilentProcessExit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LsassSilentProcessExit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LsassSilentProcessExit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LsassSilentProcessExit_offensive_tool_keyword = /\/LsassSilentProcessExit\.git/ nocase ascii wide
                        $string2_LsassSilentProcessExit_offensive_tool_keyword = /\\LsassSilentProcessExit/ nocase ascii wide
                        $string3_LsassSilentProcessExit_offensive_tool_keyword = /\\SilentProcessExit\.sln/ nocase ascii wide
                        $string4_LsassSilentProcessExit_offensive_tool_keyword = "887e0ff0707e46e7f309f6e12eaddd4161b6b3aa88a705857ac55590cdc4c64a" nocase ascii wide
                        $string5_LsassSilentProcessExit_offensive_tool_keyword = "daf3ed8ab5cb22d59e4b1de343f15e343c7e2383547f38f550b1e18a3cf8d11d" nocase ascii wide
                        $string6_LsassSilentProcessExit_offensive_tool_keyword = "deepinstinct/LsassSilentProcessExit" nocase ascii wide
                        $string7_LsassSilentProcessExit_offensive_tool_keyword = "E82BCAD1-0D2B-4E95-B382-933CF78A8128" nocase ascii wide
                        $string8_LsassSilentProcessExit_offensive_tool_keyword = /LsassSilentProcessExit\.cpp/ nocase ascii wide
                        $string9_LsassSilentProcessExit_offensive_tool_keyword = /LsassSilentProcessExit\.exe/ nocase ascii wide
                        $string10_LsassSilentProcessExit_offensive_tool_keyword = /LsassSilentProcessExit\.vcxproj/ nocase ascii wide
                        $string11_LsassSilentProcessExit_offensive_tool_keyword = "LsassSilentProcessExit-master" nocase ascii wide
                        $string12_LsassSilentProcessExit_offensive_tool_keyword = /Setting\sup\sGFlags\s\&\sSilentProcessExit\ssettings\sin\sregistry\?/ nocase ascii wide
                        $string13_LsassSilentProcessExit_offensive_tool_keyword = /SilentProcessExitRegistrySetter\.cpp/ nocase ascii wide
                        $string14_LsassSilentProcessExit_offensive_tool_keyword = /SilentProcessExitRegistrySetter\.exe/ nocase ascii wide

    condition:
        any of them
}