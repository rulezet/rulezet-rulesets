rule webshell_php_icescorpion
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the IceScorpion webshell based on decryption routines used in the shell."
        date = "2022-01-17"
        hash1 = "5af4788d1a61009361b37e8db65deecbfea595ef99c3cf920d33d9165b794972"
        os = "all"
        os_arch = "all"
        reference = "https://www.codenong.com/cs106064226/"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-09-20T11:04:50Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6374
        version = 4

    strings:
        $s1 = "[$i+1&15];"
        $s2 = "openssl_decrypt"

    condition:
        filesize < 10KB and
        all of them
}