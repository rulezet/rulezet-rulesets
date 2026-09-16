rule apt_delivery_macro_lazypine_jeus_b: LazyPine
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects macros used by the LazyPine threat actor to distribute AppleJeus."
        date = "2022-11-03"
        hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2025-05-21T15:13:39Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 8493
        version = 3

    strings:
        $a1 = ", vbDirectory) = \"\" Then" ascii
        $a2 = ".Caption & " ascii
        $a3 = ".nodeTypedValue" ascii
        $a4 = ".Application.Visible = False" ascii
        $a5 = " MkDir (" ascii

    condition:
        all of ($a*)
}