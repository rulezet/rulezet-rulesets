rule WIN32_MAL_TROJ_UPATRE_SMBG : TROJAN UPATRE
{
    meta:
        description = "Detects UPATRE Trojan variant."
        author = "Auto-generated rule"
        reference = "Not provided"
        sharing = "TLP:WHITE"
                        techniques = "Scripting:Data Obfuscation:Indicator Removal on Host:User Execution:Execution through Module Load:Reflective Loading"
        mitre_att = "T1064:T1001:T1070:T1204:T1129:T1218"
        scan_type = "file"
        dname = "TROJ_UPATRE.SMBG"
        ml_probability_score = "99.03"
        score = 99
        file_path = "/core/upatre/d6067e1501f202563d369a09b40765d56e9be98cdf98214b634eef96abec3bb2"
        sha1_hash = "23cc3f7ade79238ce186ae093fb117a79a286217"
        sha256_hash = "d6067e1501f202563d369a09b40765d56e9be98cdf98214b634eef96abec3bb2"
        timestamp = "2024-01-31T11:14:11.886140"
        date = "2024-01-31"
        yarahub_license = "CC BY 4.0"
        yarahub_uuid = "511175aa-8ed2-4462-832d-85c42079660b"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7841e2b26f05e82ae5c1576cc9914707"
        malpedia_family = "win.upatre"
    strings:
        $byte_sequence_0 = { 7524578bd34ac1e2028b9db50500008b7b3c8b7c3b78035c3b1c8b0413 }         
        $byte_sequence_1 = { 8e243b9cac0ac0741432d0b008d1ea730681f29af3a7c1fec875f2ebe7925ac3 }         
        $byte_sequence_2 = { 03fa8979048b1c96b9180000002bc32bca5fd3e88b4c964403c18b8e88000000 }         

    condition:
        all of them
}