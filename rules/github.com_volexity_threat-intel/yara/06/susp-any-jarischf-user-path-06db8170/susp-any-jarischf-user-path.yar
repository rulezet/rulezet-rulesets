rule susp_any_jarischf_user_path
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2024-04-15T13:48:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10424
        version = 4

    strings:
        $proj_1 = "/home/jarischf/"

    condition:
        any of ($proj_*)
}