rule WIN32_MAL_TROJ_DARKME : TROJAN DARKME
{
    meta:
        description = "Detects DARKME trojan variants."
        author = "Jesper Mikkelsen"
        reference = "https://www.trendmicro.com/en_us/research/24/b/cve202421412-water-hydra-targets-traders-with-windows-defender-s.html"
        sharing = "TLP:WHITE"
                        techniques = "Scripting:Data Obfuscation:Template Injection:Reflective Loading"
        mitre_att = "T1064:T1001:T1221:T1218"
        scan_type = "file"
        dname = "Trojan.Win32.DARKME.A"
        ml_probability_score = "98.97"
        score = 98
        file_path = "/core/DARKME/252351cb1fb743379b4072903a5f6c5d29774bf1957defd9a7e19890b3f84146"
        sha1_hash = "0b9a82356134087c4bb62f78496b5461b9fcc572"
        sha256_hash = "252351cb1fb743379b4072903a5f6c5d29774bf1957defd9a7e19890b3f84146"
        timestamp = "2024-02-13T20:19:25.574074"
        date = "2024-02-13"
        yarahub_license = "CC BY 4.0"
        yarahub_uuid = "511175aa-8ed2-4462-832d-85c42079660a"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3453d05a0acbd06c8774c2ba16644a9f"
    strings:
        $byte_sequence_0 = { 706cf268ffffffff00000000d06d816bb05a314be01c816b5069816b1045 }         
        $byte_sequence_1 = { 816be092816bb01c816b60732c4b9093816b000000000388046612af0f666790 }         
        $byte_sequence_2 = { 056600460166ef60106651e20066d4681066d3a70f6654f704661b350f665aae }         
        $byte_sequence_3 = { 0f6623310f6623a30066c227046687a70f666544016672d801661fa80f661f }         
        $byte_sequence_4 = { a90f6635dd0066ad870466 }         
        $byte_sequence_5 = { 23570e6678ce03660388046612af0f668769106688830366d6c51066345d }         
        $byte_sequence_6 = { 0f6600460166ef6010660d161166d4d901663b9b056651e2006627 }         
        $byte_sequence_7 = { 670566d4681066d3a70f663bff0066de2b1166151911663eda01666dd70166af }         
        $byte_sequence_8 = { 0e0f665aae0f66a0d40e66f1d9006634c80e6623a30066b36805665f2804 }         
        $byte_sequence_9 = { 668db70e66a53f0f66c227046687a70f66f714116662660566e1570e666544 }         
        $byte_sequence_10 = { 0166ce39046611570e66ee030f }         
        $byte_sequence_11 = { 89048d44ca0210eb27837d0cfb75146af4ff15c40103108b5508 }         
        $byte_sequence_12 = { c785e4eeffff1c940210eb0ac785e4eeffffcc9102108b45180fbe0885c9740c }         
        $byte_sequence_13 = { 740cc785c8eefffffc930210eb0ac785c8eeffffcc9102108b95eceeffff52 }         

    condition:
        any of them
}