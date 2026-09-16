rule RemotePipeList
{
    meta:
        description = "Detection patterns for the tool 'RemotePipeList' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemotePipeList"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\[\+\]\sConnected\sto\s\\\\\\\\.{0,1000}\\\\IPC\$/ nocase ascii wide
                        $string2 = /\[\+\]\sPipe\slisting\:/ nocase ascii wide
                        $string3 = "70BCFFDB-AE25-4BEA-BF0E-09DF06B7DBC4" nocase ascii wide
                        $string4 = /beacon_command_detail\(\\"remotepipelist\\"/ nocase ascii wide
                        $string5 = "List the named pipes on a remote system" nocase ascii wide
                        $string6 = "namespace RemotePipeList" nocase ascii wide
                        $string7 = /outflank_stage1\.implant/ nocase ascii wide
                        $string8 = "remotepipelist " nocase ascii wide
                        $string9 = "RemotePipeList is x64 only" nocase ascii wide
                        $string10 = /RemotePipeList\.cna/ nocase ascii wide
                        $string11 = /RemotePipeList\.exe/ nocase ascii wide
                        $string12 = /stage1\-remotepipelist\.py/ nocase ascii wide

    condition:
        any of them
}