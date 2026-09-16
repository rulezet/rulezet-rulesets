rule PipeViewer_
{
    meta:
        description = "Detection patterns for the tool 'PipeViewer ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PipeViewer "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PipeViewer\.exe/ nocase ascii wide
                        $string2 = /\/PipeViewer\.git/ nocase ascii wide
                        $string3 = /\/PipeViewer\.sln/ nocase ascii wide
                        $string4 = /\/PipeViewer\/Program\.cs/ nocase ascii wide
                        $string5 = /\\PipeViewer\.exe/ nocase ascii wide
                        $string6 = /\\PipeViewer\.sln/ nocase ascii wide
                        $string7 = /\\PipeViewer\\Program\.cs/ nocase ascii wide
                        $string8 = "2419CEDC-BF3A-4D8D-98F7-6403415BEEA4" nocase ascii wide
                        $string9 = "cyberark/PipeViewer" nocase ascii wide
                        $string10 = /NamedPipeServer\.ps1/ nocase ascii wide
                        $string11 = /OLDNamedPipeServer\.ps1/ nocase ascii wide
                        $string12 = /PipeViewer\.csproj/ nocase ascii wide
                        $string13 = /PipeViewer_v1\.1\.zip/ nocase ascii wide
                        $string14 = "PipeViewer-main" nocase ascii wide

    condition:
        any of them
}