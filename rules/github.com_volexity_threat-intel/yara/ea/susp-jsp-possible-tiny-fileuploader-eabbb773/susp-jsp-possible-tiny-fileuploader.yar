rule susp_jsp_possible_tiny_fileuploader
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects small .jsp files which likely have a capability to handle file uploads. These may or may not be malicious, but are often the initial webshell of choice when initially breaching a webserver."
        date = "2022-06-01"
        hash1 = "4addb9bc9e5e1af8fda63589f6b3fc038ccfd651230fa3fa61814ad080e95a12"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-07-30T09:45:42Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6787
        version = 2

    strings:
                $required1 = "request." ascii
                $required2 = "java.io.FileOutputStream" ascii
        $required3 = ".write" ascii

        $encoding1 = "java.util.Base64" ascii
        $encoding2 = "crypto.Cipher" ascii
        $encoding3 = ".misc.BASE64Decoder" ascii

    condition:
        (
            filesize < 4KB and
            all of ($required*) and
            any of ($encoding*)
        )
        or
        (
            filesize < 600 and
            all of ($required*)
        )
}