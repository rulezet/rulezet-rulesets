rule rule_RemotePipeList_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RemotePipeList' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemotePipeList"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RemotePipeList_offensive_tool_keyword = /\[\+\]\sConnected\sto\s\\\\\\\\.{0,1000}\\\\IPC\$/ nocase ascii wide
                        $string2_RemotePipeList_offensive_tool_keyword = /\[\+\]\sPipe\slisting\:/ nocase ascii wide
                        $string3_RemotePipeList_offensive_tool_keyword = "70BCFFDB-AE25-4BEA-BF0E-09DF06B7DBC4" nocase ascii wide
                        $string4_RemotePipeList_offensive_tool_keyword = /beacon_command_detail\(\\"remotepipelist\\"/ nocase ascii wide
                        $string5_RemotePipeList_offensive_tool_keyword = "List the named pipes on a remote system" nocase ascii wide
                        $string6_RemotePipeList_offensive_tool_keyword = "namespace RemotePipeList" nocase ascii wide
                        $string7_RemotePipeList_offensive_tool_keyword = /outflank_stage1\.implant/ nocase ascii wide
                        $string8_RemotePipeList_offensive_tool_keyword = "remotepipelist " nocase ascii wide
                        $string9_RemotePipeList_offensive_tool_keyword = "RemotePipeList is x64 only" nocase ascii wide
                        $string10_RemotePipeList_offensive_tool_keyword = /RemotePipeList\.cna/ nocase ascii wide
                        $string11_RemotePipeList_offensive_tool_keyword = /RemotePipeList\.exe/ nocase ascii wide
                        $string12_RemotePipeList_offensive_tool_keyword = /stage1\-remotepipelist\.py/ nocase ascii wide

    condition:
        any of them
}