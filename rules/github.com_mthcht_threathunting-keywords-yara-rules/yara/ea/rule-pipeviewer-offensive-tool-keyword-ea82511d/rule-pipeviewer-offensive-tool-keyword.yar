rule rule_PipeViewer__offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PipeViewer ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PipeViewer "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PipeViewer__offensive_tool_keyword = /\/PipeViewer\.exe/ nocase ascii wide
                        $string2_PipeViewer__offensive_tool_keyword = /\/PipeViewer\.git/ nocase ascii wide
                        $string3_PipeViewer__offensive_tool_keyword = /\/PipeViewer\.sln/ nocase ascii wide
                        $string4_PipeViewer__offensive_tool_keyword = /\/PipeViewer\/Program\.cs/ nocase ascii wide
                        $string5_PipeViewer__offensive_tool_keyword = /\\PipeViewer\.exe/ nocase ascii wide
                        $string6_PipeViewer__offensive_tool_keyword = /\\PipeViewer\.sln/ nocase ascii wide
                        $string7_PipeViewer__offensive_tool_keyword = /\\PipeViewer\\Program\.cs/ nocase ascii wide
                        $string8_PipeViewer__offensive_tool_keyword = "2419CEDC-BF3A-4D8D-98F7-6403415BEEA4" nocase ascii wide
                        $string9_PipeViewer__offensive_tool_keyword = "cyberark/PipeViewer" nocase ascii wide
                        $string10_PipeViewer__offensive_tool_keyword = /NamedPipeServer\.ps1/ nocase ascii wide
                        $string11_PipeViewer__offensive_tool_keyword = /OLDNamedPipeServer\.ps1/ nocase ascii wide
                        $string12_PipeViewer__offensive_tool_keyword = /PipeViewer\.csproj/ nocase ascii wide
                        $string13_PipeViewer__offensive_tool_keyword = /PipeViewer_v1\.1\.zip/ nocase ascii wide
                        $string14_PipeViewer__offensive_tool_keyword = "PipeViewer-main" nocase ascii wide

    condition:
        any of them
}