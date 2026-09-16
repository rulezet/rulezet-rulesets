rule AppProxyC2
{
    meta:
        description = "Detection patterns for the tool 'AppProxyC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AppProxyC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AppProxyC2\.git/ nocase ascii wide
                        $string2 = /\\AppProxyC2\./ nocase ascii wide
                        $string3 = "00de5c3931a567291bf9893e217004b8d6d7fd834798e80a60c7e97ac9d1f346" nocase ascii wide
                        $string4 = "018cedf55d51bc510037225619f98f49b5138d842f3d375e1cd880bb102e047e" nocase ascii wide
                        $string5 = "1A99EBED-6E53-469F-88B7-F4C3D2C96B07" nocase ascii wide
                        $string6 = "4d76a28ba8830185fde42e139a27d7bd8197f33810b06fcfb7980c8ddba589cf" nocase ascii wide
                        $string7 = "57c7c32de040ad8525da2c58585fe1c0e7bfd848b81308015a055e81d8cb5492" nocase ascii wide
                        $string8 = "8443F171-603C-499C-B6A6-F4F6910FD1D9" nocase ascii wide
                        $string9 = "App Proxy ExternalC2 POC by @_xpn_" nocase ascii wide
                        $string10 = /AppProxyC2CertificateCreator\.exe/ nocase ascii wide
                        $string11 = "d97f43bd7924dfd635d36d53e2bf95c850f36bf2210d159aa602b87162aceaa6" nocase ascii wide
                        $string12 = "xpn/AppProxyC2" nocase ascii wide

    condition:
        any of them
}