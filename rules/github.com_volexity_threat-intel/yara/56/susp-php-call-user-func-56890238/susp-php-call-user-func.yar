rule susp_php_call_user_func
{
    meta:
        author = "threatintel@volexity.com"
        description = "Webshells using call_user_func() function against an object from a file input or POST variable."
        date = "2021-06-16"
        hash1 = "40b053a2f3c8f47d252b960a9807b030b463ef793228b1670eda89f07b55b252"
        os = "win,linux"
        os_arch = "all"
        reference = "https://zhuanlan.zhihu.com/p/354906657"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-07-30T10:21:42Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 5582
        version = 4

    strings:
        $s1 = "@call_user_func(new C()" wide ascii

    condition:
        $s1
}