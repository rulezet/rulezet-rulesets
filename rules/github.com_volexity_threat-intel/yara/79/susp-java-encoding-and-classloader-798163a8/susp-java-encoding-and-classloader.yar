rule susp_java_encoding_and_classloader
{
    meta:
        author = "threatintel@volexity.com"
        description = "Identifies suspicious java-based files which have all the ingredients required for a webshell which expects the attacker to provide a Class to load in memory."
        date = "2022-04-07"
        hash1 = "0d5dc54ef77bc18c4c5582dca4619905605668cffcccc3829e43c6d3e14ef216"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-07-30T09:19:16Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6688
        version = 3

    strings:
        $s1 = "javax.crypto.spec.SecretKeySpec" ascii
        $s2 = "java/security/SecureClassLoader" ascii
        $s3 = "sun.misc.BASE64Decoder" ascii

    condition:
        filesize < 50KB and
        all of them
}