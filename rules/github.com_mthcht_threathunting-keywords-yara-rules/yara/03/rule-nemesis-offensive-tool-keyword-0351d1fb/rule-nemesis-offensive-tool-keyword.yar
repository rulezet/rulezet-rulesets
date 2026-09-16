rule rule_nemesis_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nemesis' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nemesis"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nemesis_offensive_tool_keyword = /\s11_Credentials\.py/ nocase ascii wide
                        $string2_nemesis_offensive_tool_keyword = /\s13_NoseyParker\.py/ nocase ascii wide
                        $string3_nemesis_offensive_tool_keyword = /\s17_Custom_Cracklist\.py/ nocase ascii wide
                        $string4_nemesis_offensive_tool_keyword = /\s9_DPAPI\.py/ nocase ascii wide
                        $string5_nemesis_offensive_tool_keyword = /\sbof_reg_collect_parser\.py/ nocase ascii wide
                        $string6_nemesis_offensive_tool_keyword = /\schromium_history\.py/ nocase ascii wide
                        $string7_nemesis_offensive_tool_keyword = /\schromium_logins\.py/ nocase ascii wide
                        $string8_nemesis_offensive_tool_keyword = /\scrack_list\sclient_wordlists\.py/ nocase ascii wide
                        $string9_nemesis_offensive_tool_keyword = /\scrack_list\scracklist_api\.py/ nocase ascii wide
                        $string10_nemesis_offensive_tool_keyword = /\scrack_list\sdictionary\.py/ nocase ascii wide
                        $string11_nemesis_offensive_tool_keyword = /\scrack_list\swordlist\.py/ nocase ascii wide
                        $string12_nemesis_offensive_tool_keyword = /\sdpapi_domain_backupkey\.py/ nocase ascii wide
                        $string13_nemesis_offensive_tool_keyword = /\sdpapi_masterkey\.py/ nocase ascii wide
                        $string14_nemesis_offensive_tool_keyword = /\sDPAPImk2john\.py/ nocase ascii wide
                        $string15_nemesis_offensive_tool_keyword = /\sjohn_the_ripper_cracker\.py/ nocase ascii wide
                        $string16_nemesis_offensive_tool_keyword = /\s\-m\senrichment\.cli\.submit_to_nemesis/ nocase ascii wide
                        $string17_nemesis_offensive_tool_keyword = /\snemesis_connector\.py/ nocase ascii wide
                        $string18_nemesis_offensive_tool_keyword = /\snemesis_db\.py/ nocase ascii wide
                        $string19_nemesis_offensive_tool_keyword = /\snemesis_reg_collect_parser\.py/ nocase ascii wide
                        $string20_nemesis_offensive_tool_keyword = /\snemesis\-cli\.py/ nocase ascii wide
                        $string21_nemesis_offensive_tool_keyword = /\soffice2john\.py/ nocase ascii wide
                        $string22_nemesis_offensive_tool_keyword = /\spasswd\.py/
                        $string23_nemesis_offensive_tool_keyword = /\spassword_cracker\.py/ nocase ascii wide
                        $string24_nemesis_offensive_tool_keyword = /\spdf2john\.py/ nocase ascii wide
                        $string25_nemesis_offensive_tool_keyword = /\sreg_hive_sam\.py/ nocase ascii wide
                        $string26_nemesis_offensive_tool_keyword = /\sreg_hive_security\.py/ nocase ascii wide
                        $string27_nemesis_offensive_tool_keyword = /\sreg_hive_system\.py/ nocase ascii wide
                        $string28_nemesis_offensive_tool_keyword = /\sseatbelt_json\.py/ nocase ascii wide
                        $string29_nemesis_offensive_tool_keyword = /\ssecretsdump\.py/ nocase ascii wide
                        $string30_nemesis_offensive_tool_keyword = /\ssliver_pb2\.py/ nocase ascii wide
                        $string31_nemesis_offensive_tool_keyword = /\ssliver_pb2_grpc\.py/ nocase ascii wide
                        $string32_nemesis_offensive_tool_keyword = /\ssubmit_to_nemesis\.py/ nocase ascii wide
                        $string33_nemesis_offensive_tool_keyword = /\ssubmit_to_nemesis\.sh/ nocase ascii wide
                        $string34_nemesis_offensive_tool_keyword = " --user 'nemesis:" nocase ascii wide
                        $string35_nemesis_offensive_tool_keyword = /\.\/agscript\s.{0,100}\snemesis\-bot\s/
                        $string36_nemesis_offensive_tool_keyword = /\/11_Credentials\.py/ nocase ascii wide
                        $string37_nemesis_offensive_tool_keyword = /\/13_NoseyParker\.py/ nocase ascii wide
                        $string38_nemesis_offensive_tool_keyword = /\/17_Custom_Cracklist\.py/ nocase ascii wide
                        $string39_nemesis_offensive_tool_keyword = /\/9_DPAPI\.py/ nocase ascii wide
                        $string40_nemesis_offensive_tool_keyword = /\/bof_reg_collect_parser\.py/ nocase ascii wide
                        $string41_nemesis_offensive_tool_keyword = /\/chromium_history\.py/ nocase ascii wide
                        $string42_nemesis_offensive_tool_keyword = /\/chromium_logins\.py/ nocase ascii wide
                        $string43_nemesis_offensive_tool_keyword = "/cobaltstrike-nemesis-connector/" nocase ascii wide
                        $string44_nemesis_offensive_tool_keyword = /\/crack_list\/client_wordlists\.py/ nocase ascii wide
                        $string45_nemesis_offensive_tool_keyword = /\/crack_list\/cracklist_api\.py/ nocase ascii wide
                        $string46_nemesis_offensive_tool_keyword = /\/crack_list\/dictionary\.py/ nocase ascii wide
                        $string47_nemesis_offensive_tool_keyword = /\/crack_list\/wordlist\.py/ nocase ascii wide
                        $string48_nemesis_offensive_tool_keyword = /\/custom_crack_list\.txt/ nocase ascii wide
                        $string49_nemesis_offensive_tool_keyword = /\/dpapi_domain_backupkey\.py/ nocase ascii wide
                        $string50_nemesis_offensive_tool_keyword = /\/dpapi_masterkey\.py/ nocase ascii wide
                        $string51_nemesis_offensive_tool_keyword = /\/DPAPImk2john\.py/ nocase ascii wide
                        $string52_nemesis_offensive_tool_keyword = /\/john_the_ripper_cracker\.py/ nocase ascii wide
                        $string53_nemesis_offensive_tool_keyword = /\/Nemesis\.git/ nocase ascii wide
                        $string54_nemesis_offensive_tool_keyword = /\/nemesis_connector\.py/ nocase ascii wide
                        $string55_nemesis_offensive_tool_keyword = /\/nemesis_db\.py/ nocase ascii wide
                        $string56_nemesis_offensive_tool_keyword = /\/nemesis_reg_collect_parser\.py/ nocase ascii wide
                        $string57_nemesis_offensive_tool_keyword = /\/nemesis\-cli\.py/ nocase ascii wide
                        $string58_nemesis_offensive_tool_keyword = /\/office2john\.py/ nocase ascii wide
                        $string59_nemesis_offensive_tool_keyword = "/opt/cobaltstrike-nemesis"
                        $string60_nemesis_offensive_tool_keyword = /\/passwd\.py/
                        $string61_nemesis_offensive_tool_keyword = /\/password_cracker\.py/ nocase ascii wide
                        $string62_nemesis_offensive_tool_keyword = /\/passwordcracker\.Dockerfile/ nocase ascii wide
                        $string63_nemesis_offensive_tool_keyword = "/passwordcracker/" nocase ascii wide
                        $string64_nemesis_offensive_tool_keyword = /\/pdf2john\.py/ nocase ascii wide
                        $string65_nemesis_offensive_tool_keyword = /\/reg_hive_sam\.py/ nocase ascii wide
                        $string66_nemesis_offensive_tool_keyword = /\/reg_hive_security\.py/ nocase ascii wide
                        $string67_nemesis_offensive_tool_keyword = /\/reg_hive_system\.py/ nocase ascii wide
                        $string68_nemesis_offensive_tool_keyword = /\/seatbelt_json\.py/ nocase ascii wide
                        $string69_nemesis_offensive_tool_keyword = /\/secretsdump\.py/ nocase ascii wide
                        $string70_nemesis_offensive_tool_keyword = /\/sliver_pb2\.py/ nocase ascii wide
                        $string71_nemesis_offensive_tool_keyword = /\/sliver_pb2_grpc\.py/ nocase ascii wide
                        $string72_nemesis_offensive_tool_keyword = /\/submit_to_nemesis\.py/ nocase ascii wide
                        $string73_nemesis_offensive_tool_keyword = /\/submit_to_nemesis\.sh/ nocase ascii wide
                        $string74_nemesis_offensive_tool_keyword = /\/submit_to_nemesis\.yaml/ nocase ascii wide
                        $string75_nemesis_offensive_tool_keyword = /\/wordlists\/top_10000\.txt/ nocase ascii wide
                        $string76_nemesis_offensive_tool_keyword = /\/wordlists\/top_100000\.txt/ nocase ascii wide
                        $string77_nemesis_offensive_tool_keyword = ":8080/yara/file" nocase ascii wide
                        $string78_nemesis_offensive_tool_keyword = /\\Seatbelt\.exe/ nocase ascii wide
                        $string79_nemesis_offensive_tool_keyword = "AWS_BUCKET=nemesis-test" nocase ascii wide
                        $string80_nemesis_offensive_tool_keyword = "AWS_KMS_KEY_ALIAS=nemesis-dev" nocase ascii wide
                        $string81_nemesis_offensive_tool_keyword = "class Plugin::Nemesis < Msf::Plugin" nocase ascii wide
                        $string82_nemesis_offensive_tool_keyword = "cobaltstrike-nemesis-connector" nocase ascii wide
                        $string83_nemesis_offensive_tool_keyword = /create_nemesis_db\(/ nocase ascii wide
                        $string84_nemesis_offensive_tool_keyword = /create_nemesis_db_pool\(/ nocase ascii wide
                        $string85_nemesis_offensive_tool_keyword = /def\snemesis_post_data\(/ nocase ascii wide
                        $string86_nemesis_offensive_tool_keyword = "export NEMESIS_BASE_URL" nocase ascii wide
                        $string87_nemesis_offensive_tool_keyword = "export NEMESIS_CREDS" nocase ascii wide
                        $string88_nemesis_offensive_tool_keyword = /file_parsers\/group_policy_preferences\.py/ nocase ascii wide
                        $string89_nemesis_offensive_tool_keyword = /getLogger\(\\"NemesisConnector\\"\)/ nocase ascii wide
                        $string90_nemesis_offensive_tool_keyword = "http://nemesis/file" nocase ascii wide
                        $string91_nemesis_offensive_tool_keyword = "http://nemesis/yara" nocase ascii wide
                        $string92_nemesis_offensive_tool_keyword = /http\:\/\/nemesis\-es\-http\.default\.svc\.cluster\.local\:9200/ nocase ascii wide
                        $string93_nemesis_offensive_tool_keyword = "http://nemesis-es-internal-http:9200" nocase ascii wide
                        $string94_nemesis_offensive_tool_keyword = /http\:\/\/nemesis\-kb\-http\.default\.svc\.cluster\.local\:5601/ nocase ascii wide
                        $string95_nemesis_offensive_tool_keyword = "http://nemesis-kb-http:5601" nocase ascii wide
                        $string96_nemesis_offensive_tool_keyword = /https\:\/\/nemesis\..{0,100}\.com\/api\// nocase ascii wide
                        $string97_nemesis_offensive_tool_keyword = /logging\.getLogger\(\\"nemesis\\"\)/ nocase ascii wide
                        $string98_nemesis_offensive_tool_keyword = /modules\/nemesis\.rb/ nocase ascii wide
                        $string99_nemesis_offensive_tool_keyword = "Nemesis frontend HTTP server endpoint" nocase ascii wide
                        $string100_nemesis_offensive_tool_keyword = "nemesis:Qwerty12345@" nocase ascii wide
                        $string101_nemesis_offensive_tool_keyword = /nemesis\@nemesis\.com/ nocase ascii wide
                        $string102_nemesis_offensive_tool_keyword = /nemesis\@nemesis\.local/ nocase ascii wide
                        $string103_nemesis_offensive_tool_keyword = "NEMESIS_API_URL" nocase ascii wide
                        $string104_nemesis_offensive_tool_keyword = "NEMESIS_HTTP_SERVER " nocase ascii wide
                        $string105_nemesis_offensive_tool_keyword = /nemesis_post_file\(/ nocase ascii wide
                        $string106_nemesis_offensive_tool_keyword = "nemesis-rabbitmq-discovery" nocase ascii wide
                        $string107_nemesis_offensive_tool_keyword = /nemesis\-rabbitmq\-discovery\.default\.svc\.cluster\.local/ nocase ascii wide
                        $string108_nemesis_offensive_tool_keyword = "NemesisRabbitMQProducer" nocase ascii wide
                        $string109_nemesis_offensive_tool_keyword = /plugins\/nemesis\.rb/ nocase ascii wide
                        $string110_nemesis_offensive_tool_keyword = "sample_files/passwd" nocase ascii wide
                        $string111_nemesis_offensive_tool_keyword = /Seatbelt\.Commands\.Windows/ nocase ascii wide
                        $string112_nemesis_offensive_tool_keyword = "skaffold run -m nemesis " nocase ascii wide
                        $string113_nemesis_offensive_tool_keyword = "SpecterOps/Nemesis" nocase ascii wide
                        $string114_nemesis_offensive_tool_keyword = /Staring\sNemesis\sBot\.\sTeamserver/ nocase ascii wide
                        $string115_nemesis_offensive_tool_keyword = /webapi\/nemesis_api\.py/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}