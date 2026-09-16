import "math"
rule webshell_php_str_replace_create_func
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for obfuscated PHP shells where create_function() is obfuscated using str_replace and then called using no arguments."
        date = "2022-04-04"
        hash1 = "c713d13af95f2fe823d219d1061ec83835bf0281240fba189f212e7da0d94937"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2025-06-18T15:11:16Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6675
        version = 5

    strings:
                $s = "=str_replace(" ascii
                        $anon_func = "(''," ascii

    condition:
        filesize < 100KB and
        uint32be(0) == 0x3c3f7068 and
        all of them and
        for any i in (1..math.min(#s,100)):
            (
                for any j in (1..math.min(#anon_func,100)):
                    (
                        uint16be(@s[i]-2) == uint16be(@anon_func[j]-2)
                    )
            )
}