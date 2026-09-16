rule rule_WebSocketReverseShellDotNet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WebSocketReverseShellDotNet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebSocketReverseShellDotNet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WebSocketReverseShellDotNet_offensive_tool_keyword = /\/reverseShell\-1\.0\.1\-zip\.zip/ nocase ascii wide
                        $string2_WebSocketReverseShellDotNet_offensive_tool_keyword = ":8070/reverseShellClients" nocase ascii wide
                        $string3_WebSocketReverseShellDotNet_offensive_tool_keyword = /\\BrowserExfelterator\.cs/ nocase ascii wide
                        $string4_WebSocketReverseShellDotNet_offensive_tool_keyword = /\\commands\\CameraScreenShot\.cs/ nocase ascii wide
                        $string5_WebSocketReverseShellDotNet_offensive_tool_keyword = /\\DiscordTokenExfilterater\.cs/ nocase ascii wide
                        $string6_WebSocketReverseShellDotNet_offensive_tool_keyword = /\\Obfuscar\.Console\.exe/ nocase ascii wide
                        $string7_WebSocketReverseShellDotNet_offensive_tool_keyword = /\\PersistsMalware\.cs/ nocase ascii wide
                        $string8_WebSocketReverseShellDotNet_offensive_tool_keyword = /\\TokenExfiltereter\.cs/ nocase ascii wide
                        $string9_WebSocketReverseShellDotNet_offensive_tool_keyword = ">Obfuscar Console Utility<" nocase ascii wide
                        $string10_WebSocketReverseShellDotNet_offensive_tool_keyword = "44782077d86a1fd173b94e020c23dc511a58fe77e055116014c30f8ecc4ead91" nocase ascii wide
                        $string11_WebSocketReverseShellDotNet_offensive_tool_keyword = "474B99B7-66C4-4AC2-8AD3-065DD13DDDFF" nocase ascii wide
                        $string12_WebSocketReverseShellDotNet_offensive_tool_keyword = "543111f63af0bba0de982e608dde5289571d227b941c74131a8b9df9a8dc2609" nocase ascii wide
                        $string13_WebSocketReverseShellDotNet_offensive_tool_keyword = "950bb21485106b135bbe1e28b8b7f74652cadeb9ae8c68342f0ee8c91ce8306c" nocase ascii wide
                        $string14_WebSocketReverseShellDotNet_offensive_tool_keyword = /c2\-server\.mtattab\.com\/reverseShellClients/ nocase ascii wide
                        $string15_WebSocketReverseShellDotNet_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\:8070/ nocase ascii wide
                        $string16_WebSocketReverseShellDotNet_offensive_tool_keyword = /password\-hijaker\.exe/ nocase ascii wide
                        $string17_WebSocketReverseShellDotNet_offensive_tool_keyword = "RemoteShellCodeInjection-master" nocase ascii wide
                        $string18_WebSocketReverseShellDotNet_offensive_tool_keyword = /RemoteShellCodeInjection\-master\.zip/ nocase ascii wide
                        $string19_WebSocketReverseShellDotNet_offensive_tool_keyword = /schtasks\s\/create\s\/tn\s.{0,1000}Constants\.PERSISTENCE_WINDOWS_TASK\s\+/ nocase ascii wide
                        $string20_WebSocketReverseShellDotNet_offensive_tool_keyword = "WebSocketReverseShellDotNet" nocase ascii wide

    condition:
        any of them
}