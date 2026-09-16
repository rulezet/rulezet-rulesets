rule rule_AppProxyC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AppProxyC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AppProxyC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AppProxyC2_offensive_tool_keyword = /\/AppProxyC2\.git/ nocase ascii wide
                        $string2_AppProxyC2_offensive_tool_keyword = /\\AppProxyC2\./ nocase ascii wide
                        $string3_AppProxyC2_offensive_tool_keyword = "00de5c3931a567291bf9893e217004b8d6d7fd834798e80a60c7e97ac9d1f346" nocase ascii wide
                        $string4_AppProxyC2_offensive_tool_keyword = "018cedf55d51bc510037225619f98f49b5138d842f3d375e1cd880bb102e047e" nocase ascii wide
                        $string5_AppProxyC2_offensive_tool_keyword = "1A99EBED-6E53-469F-88B7-F4C3D2C96B07" nocase ascii wide
                        $string6_AppProxyC2_offensive_tool_keyword = "4d76a28ba8830185fde42e139a27d7bd8197f33810b06fcfb7980c8ddba589cf" nocase ascii wide
                        $string7_AppProxyC2_offensive_tool_keyword = "57c7c32de040ad8525da2c58585fe1c0e7bfd848b81308015a055e81d8cb5492" nocase ascii wide
                        $string8_AppProxyC2_offensive_tool_keyword = "8443F171-603C-499C-B6A6-F4F6910FD1D9" nocase ascii wide
                        $string9_AppProxyC2_offensive_tool_keyword = "App Proxy ExternalC2 POC by @_xpn_" nocase ascii wide
                        $string10_AppProxyC2_offensive_tool_keyword = /AppProxyC2CertificateCreator\.exe/ nocase ascii wide
                        $string11_AppProxyC2_offensive_tool_keyword = "d97f43bd7924dfd635d36d53e2bf95c850f36bf2210d159aa602b87162aceaa6" nocase ascii wide
                        $string12_AppProxyC2_offensive_tool_keyword = "xpn/AppProxyC2" nocase ascii wide

    condition:
        any of them
}