rule impacketremoteshell
{
    meta:
        description = "Detection patterns for the tool 'impacketremoteshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacketremoteshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sremoteshell\.py/ nocase ascii wide
                        $string2 = /\/RemoteMaintsvc\.exe/ nocase ascii wide
                        $string3 = /\/RemoteMaintsvc\.exe/ nocase ascii wide
                        $string4 = /\/remoteshell\.py/ nocase ascii wide
                        $string5 = /\\\\\.\\pipe\\RemoteMaint/ nocase ascii wide
                        $string6 = /\\\\\\\\\.\\\\pipe\\\\RemoteMaint/ nocase ascii wide
                        $string7 = /\\RemoteMaint\.sln/ nocase ascii wide
                        $string8 = /\\RemoteMaint\.vcxproj/ nocase ascii wide
                        $string9 = /\\RemoteMaintsvc\.exe/ nocase ascii wide
                        $string10 = /\\RemoteMaintsvc\.exe/ nocase ascii wide
                        $string11 = /\\remoteshell\.py/ nocase ascii wide
                        $string12 = "037f7348a66495d6502220e15f3766aa070dd12eb40b3d08d3f855c4cd77cf7f" nocase ascii wide
                        $string13 = "11ef63b9bc33b0da6d0b5593e55e460aa8aa8279eb9ad4b90a4dc2b722ffa6e1" nocase ascii wide
                        $string14 = "9e85c971331b8ad686c8d79ea81c4883d3f36a7de2071551fe5369fcf34ea3d0" nocase ascii wide
                        $string15 = "CE23F388-34F5-4543-81D1-91CD244C9CB1" nocase ascii wide
                        $string16 = /impacket\.internal_helpers/ nocase ascii wide
                        $string17 = /impacket\.smbconnection/ nocase ascii wide

    condition:
        any of them
}