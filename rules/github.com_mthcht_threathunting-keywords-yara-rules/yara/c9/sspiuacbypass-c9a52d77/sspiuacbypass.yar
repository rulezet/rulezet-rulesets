rule SspiUacBypass
{
    meta:
        description = "Detection patterns for the tool 'SspiUacBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SspiUacBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " - Bypassing UAC with SSPI Datagram Contexts" nocase ascii wide
                        $string2 = " SspiUacBypass " nocase ascii wide
                        $string3 = /\/SspiUacBypass\.git/ nocase ascii wide
                        $string4 = /\\bypassuac\.txt/ nocase ascii wide
                        $string5 = "5F4DC47F-7819-4528-9C16-C88F1BE97EC5" nocase ascii wide
                        $string6 = "antonioCoco/SspiUacBypass" nocase ascii wide
                        $string7 = /Bypass\sSuccess\!\sNow\simpersonating\sthe\sforged\stoken.{0,1000}\sLoopback\snetwork\sauth\sshould\sbe\sseen\sas\selevated\snow/ nocase ascii wide
                        $string8 = "ea49111ee3bf716e9f4643f95b5df19fd8bd7376464b2795dcfc5e07ddda35eb" nocase ascii wide
                        $string9 = "Forging a token from a fake Network Authentication through Datagram Contexts" nocase ascii wide
                        $string10 = /Invoking\sCreateSvcRpc\s\(by\s\@x86matthew/ nocase ascii wide
                        $string11 = /SspiUacBypass\.cpp/ nocase ascii wide
                        $string12 = /SspiUacBypass\.exe/ nocase ascii wide
                        $string13 = "SspiUacBypass-main" nocase ascii wide

    condition:
        any of them
}