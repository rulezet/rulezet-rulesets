rule FilelessPELoader
{
    meta:
        description = "Detection patterns for the tool 'FilelessPELoader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FilelessPELoader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAES_cryptor\.py\s/ nocase ascii wide
                        $string2 = "/FilelessPELoader" nocase ascii wide
                        $string3 = /\[\+\]\sGetPEFromRemoteServer/ nocase ascii wide
                        $string4 = /\\AES_cryptor\.py\s/ nocase ascii wide
                        $string5 = "4e2e5319f881c4a83bfeeeaf713beb1ee5ee4b19dff511abe8f05f9e2e1c3c55" nocase ascii wide
                        $string6 = "69a200568ae92a6eee56c9fcc170b088432871fb058c29459e7bf112a58d722f" nocase ascii wide
                        $string7 = "82277B35-D159-4B44-8D54-FB66EDD58D5C" nocase ascii wide
                        $string8 = "92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50" nocase ascii wide
                        $string9 = /AES_cryptor\.py\s/ nocase ascii wide
                        $string10 = "ca12dd05b0f8cff9da1c8e088808a8c6e3218eefa22c0d92469abda3888dab4d" nocase ascii wide
                        $string11 = /FilelessPELoader\.cpp/ nocase ascii wide
                        $string12 = /FilelessPELoader\.exe/ nocase ascii wide
                        $string13 = /FilelessPELoader\.sln/ nocase ascii wide
                        $string14 = /FilelessPELoader\.vcxproj/ nocase ascii wide
                        $string15 = "FilelessPELoader-main" nocase ascii wide
                        $string16 = /mimikatz\.exe/ nocase ascii wide
                        $string17 = /Trojan\:Win32\/TurtleLoader\./ nocase ascii wide

    condition:
        any of them
}