rule apt_webshell_pl_complyshell: UTA0178
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-12-13"
        description = "Detection for the COMPLYSHELL webshell."
        hash1 = "8bc8f4da98ee05c9d403d2cb76097818de0b524d90bea8ed846615e42cb031d2"
        os = "linux"
        os_arch = "all"
        report = "TIB-20231215"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-12T17:32:31Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9995
        version = 4

    strings:
        $s = "eval{my $c=Crypt::RC4->new("

    condition:
        $s
}