rule WebSocketReverseShellDotNet
{
    meta:
        description = "Detection patterns for the tool 'WebSocketReverseShellDotNet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebSocketReverseShellDotNet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/reverseShell\-1\.0\.1\-zip\.zip/ nocase ascii wide
                        $string2 = ":8070/reverseShellClients" nocase ascii wide
                        $string3 = /\\BrowserExfelterator\.cs/ nocase ascii wide
                        $string4 = /\\commands\\CameraScreenShot\.cs/ nocase ascii wide
                        $string5 = /\\DiscordTokenExfilterater\.cs/ nocase ascii wide
                        $string6 = /\\Obfuscar\.Console\.exe/ nocase ascii wide
                        $string7 = /\\PersistsMalware\.cs/ nocase ascii wide
                        $string8 = /\\TokenExfiltereter\.cs/ nocase ascii wide
                        $string9 = ">Obfuscar Console Utility<" nocase ascii wide
                        $string10 = "44782077d86a1fd173b94e020c23dc511a58fe77e055116014c30f8ecc4ead91" nocase ascii wide
                        $string11 = "474B99B7-66C4-4AC2-8AD3-065DD13DDDFF" nocase ascii wide
                        $string12 = "543111f63af0bba0de982e608dde5289571d227b941c74131a8b9df9a8dc2609" nocase ascii wide
                        $string13 = "950bb21485106b135bbe1e28b8b7f74652cadeb9ae8c68342f0ee8c91ce8306c" nocase ascii wide
                        $string14 = /c2\-server\.mtattab\.com\/reverseShellClients/ nocase ascii wide
                        $string15 = /http\:\/\/127\.0\.0\.1\:8070/ nocase ascii wide
                        $string16 = /password\-hijaker\.exe/ nocase ascii wide
                        $string17 = "RemoteShellCodeInjection-master" nocase ascii wide
                        $string18 = /RemoteShellCodeInjection\-master\.zip/ nocase ascii wide
                        $string19 = /schtasks\s\/create\s\/tn\s.{0,1000}Constants\.PERSISTENCE_WINDOWS_TASK\s\+/ nocase ascii wide
                        $string20 = "WebSocketReverseShellDotNet" nocase ascii wide

    condition:
        any of them
}