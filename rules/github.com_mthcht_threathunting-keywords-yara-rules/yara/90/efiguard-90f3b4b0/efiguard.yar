rule EfiGuard
{
    meta:
        description = "Detection patterns for the tool 'EfiGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EfiGuard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sEfiDSEFix\.cpp/ nocase ascii wide
                        $string2 = /\sUefiShell\.iso/ nocase ascii wide
                        $string3 = /\/EfiDSEFix\.cpp/ nocase ascii wide
                        $string4 = /\/EfiDSEFix\.exe/ nocase ascii wide
                        $string5 = /\/EfiGuard\.sln/ nocase ascii wide
                        $string6 = /\/EfiGuardDxe\.c/ nocase ascii wide
                        $string7 = /\/UefiShell\.iso/ nocase ascii wide
                        $string8 = /\\Boot\\EfiGuardDxe\.efi/ nocase ascii wide
                        $string9 = /\\EfiDSEFix\.cpp/ nocase ascii wide
                        $string10 = /\\EfiDSEFix\.exe/ nocase ascii wide
                        $string11 = /\\EfiGuard\.sln/ nocase ascii wide
                        $string12 = /\\EfiGuardDxe\.c/ nocase ascii wide
                        $string13 = /\\EfiGuardDxe\.h/ nocase ascii wide
                        $string14 = /\\EfiGuardDxe\\X64\\/ nocase ascii wide
                        $string15 = /\\UefiShell\.iso/ nocase ascii wide
                        $string16 = "0E4BAB8F-E6E0-47A8-8E99-8D451839967E" nocase ascii wide
                        $string17 = "B2924789-9912-4B6F-8F7B-53240AC3BA0E" nocase ascii wide
                        $string18 = "D7484EBA-6357-4D81-B355-066E28D5DF72" nocase ascii wide
                        $string19 = /EfiDSEFix\.exe\s/ nocase ascii wide
                        $string20 = "EFIGUARD_BACKDOOR_VARIABLE_NAME" nocase ascii wide
                        $string21 = /EfiGuard\-v1\.1\.zip/ nocase ascii wide
                        $string22 = /EfiGuard\-v1\.2\.zip/ nocase ascii wide
                        $string23 = /EfiGuard\-v1\.3\.zip/ nocase ascii wide
                        $string24 = /EfiGuard\-v1\.4\.zip/ nocase ascii wide
                        $string25 = /EfiGuard\-v1\.5\.zip/ nocase ascii wide
                        $string26 = /Protocol\/EfiGuard\.h/ nocase ascii wide
                        $string27 = "roodkcaBdrauGifE" nocase ascii wide

    condition:
        any of them
}