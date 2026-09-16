rule rule_SspiUacBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SspiUacBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SspiUacBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SspiUacBypass_offensive_tool_keyword = " - Bypassing UAC with SSPI Datagram Contexts" nocase ascii wide
                        $string2_SspiUacBypass_offensive_tool_keyword = " SspiUacBypass " nocase ascii wide
                        $string3_SspiUacBypass_offensive_tool_keyword = /\/SspiUacBypass\.git/ nocase ascii wide
                        $string4_SspiUacBypass_offensive_tool_keyword = /\\bypassuac\.txt/ nocase ascii wide
                        $string5_SspiUacBypass_offensive_tool_keyword = "5F4DC47F-7819-4528-9C16-C88F1BE97EC5" nocase ascii wide
                        $string6_SspiUacBypass_offensive_tool_keyword = "antonioCoco/SspiUacBypass" nocase ascii wide
                        $string7_SspiUacBypass_offensive_tool_keyword = /Bypass\sSuccess\!\sNow\simpersonating\sthe\sforged\stoken.{0,1000}\sLoopback\snetwork\sauth\sshould\sbe\sseen\sas\selevated\snow/ nocase ascii wide
                        $string8_SspiUacBypass_offensive_tool_keyword = "ea49111ee3bf716e9f4643f95b5df19fd8bd7376464b2795dcfc5e07ddda35eb" nocase ascii wide
                        $string9_SspiUacBypass_offensive_tool_keyword = "Forging a token from a fake Network Authentication through Datagram Contexts" nocase ascii wide
                        $string10_SspiUacBypass_offensive_tool_keyword = /Invoking\sCreateSvcRpc\s\(by\s\@x86matthew/ nocase ascii wide
                        $string11_SspiUacBypass_offensive_tool_keyword = /SspiUacBypass\.cpp/ nocase ascii wide
                        $string12_SspiUacBypass_offensive_tool_keyword = /SspiUacBypass\.exe/ nocase ascii wide
                        $string13_SspiUacBypass_offensive_tool_keyword = "SspiUacBypass-main" nocase ascii wide

    condition:
        any of them
}