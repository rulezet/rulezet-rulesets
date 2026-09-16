rule apt_delivery_office_macro_lazypine_jeus: LazyPine
{
    meta:
        author = "threatintel@volexity.com"
        date = "2022-11-02"
        description = "Detects malicious documents used by LazyPine in a campaign dropping the AppleJeus malware."
        hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
        os = "all"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2025-05-21T15:14:47Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 8490
        version = 7

    strings:
        $s1 = "0M8R4K" ascii
        $s2 = "bin.base64" ascii
        $s3 = "dragon" ascii
        $s4 = "Workbook_Open" ascii

    condition:
       all of ($s*)
}