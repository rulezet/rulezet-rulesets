rule susp_php_fileinput_eval
{
    meta:
        author = "threatintel@volexity.com"
        description = "Rule designed to detect PHP files which use file_get_contents() and then shortly afterwards use an eval statement."
        date = "2021-06-16"
        hash1 = "1a34c43611ee310c16acc383c10a7b8b41578c19ee85716b14ac5adbf0a13bd5"
        hash2 = "6e8874c756c009c63f715a44ca72d0cb31dc25d87d7df6ca2830fe8330580342"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-12-12T11:17:16Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 5581
        version = 5

    strings:
        $s1 = "file_get_contents(\"php://input\")"
        $s2 = "eval("

    condition:
        $s2 in (@s1[1]..(@s1[1]+512))
}