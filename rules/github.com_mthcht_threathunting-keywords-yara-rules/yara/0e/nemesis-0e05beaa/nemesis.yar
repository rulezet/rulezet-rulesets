rule nemesis
{
    meta:
        description = "Detection patterns for the tool 'nemesis' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nemesis"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s11_Credentials\.py/ nocase ascii wide
                        $string2 = /\s13_NoseyParker\.py/ nocase ascii wide
                        $string3 = /\s17_Custom_Cracklist\.py/ nocase ascii wide
                        $string4 = /\s9_DPAPI\.py/ nocase ascii wide
                        $string5 = /\sbof_reg_collect_parser\.py/ nocase ascii wide
                        $string6 = /\schromium_history\.py/ nocase ascii wide
                        $string7 = /\schromium_logins\.py/ nocase ascii wide
                        $string8 = /\scrack_list\sclient_wordlists\.py/ nocase ascii wide
                        $string9 = /\scrack_list\scracklist_api\.py/ nocase ascii wide
                        $string10 = /\scrack_list\sdictionary\.py/ nocase ascii wide
                        $string11 = /\scrack_list\swordlist\.py/ nocase ascii wide
                        $string12 = /\sdpapi_domain_backupkey\.py/ nocase ascii wide
                        $string13 = /\sdpapi_masterkey\.py/ nocase ascii wide
                        $string14 = /\sDPAPImk2john\.py/ nocase ascii wide
                        $string15 = /\sjohn_the_ripper_cracker\.py/ nocase ascii wide
                        $string16 = /\s\-m\senrichment\.cli\.submit_to_nemesis/ nocase ascii wide
                        $string17 = /\snemesis_connector\.py/ nocase ascii wide
                        $string18 = /\snemesis_db\.py/ nocase ascii wide
                        $string19 = /\snemesis_reg_collect_parser\.py/ nocase ascii wide
                        $string20 = /\snemesis\-cli\.py/ nocase ascii wide
                        $string21 = /\soffice2john\.py/ nocase ascii wide
                        $string22 = /\spasswd\.py/
                        $string23 = /\spassword_cracker\.py/ nocase ascii wide
                        $string24 = /\spdf2john\.py/ nocase ascii wide
                        $string25 = /\sreg_hive_sam\.py/ nocase ascii wide
                        $string26 = /\sreg_hive_security\.py/ nocase ascii wide
                        $string27 = /\sreg_hive_system\.py/ nocase ascii wide
                        $string28 = /\sseatbelt_json\.py/ nocase ascii wide
                        $string29 = /\ssecretsdump\.py/ nocase ascii wide
                        $string30 = /\ssliver_pb2\.py/ nocase ascii wide
                        $string31 = /\ssliver_pb2_grpc\.py/ nocase ascii wide
                        $string32 = /\ssubmit_to_nemesis\.py/ nocase ascii wide
                        $string33 = /\ssubmit_to_nemesis\.sh/ nocase ascii wide
                        $string34 = " --user 'nemesis:" nocase ascii wide
                        $string35 = /\.\/agscript\s.{0,100}\snemesis\-bot\s/
                        $string36 = /\/11_Credentials\.py/ nocase ascii wide
                        $string37 = /\/13_NoseyParker\.py/ nocase ascii wide
                        $string38 = /\/17_Custom_Cracklist\.py/ nocase ascii wide
                        $string39 = /\/9_DPAPI\.py/ nocase ascii wide
                        $string40 = /\/bof_reg_collect_parser\.py/ nocase ascii wide
                        $string41 = /\/chromium_history\.py/ nocase ascii wide
                        $string42 = /\/chromium_logins\.py/ nocase ascii wide
                        $string43 = "/cobaltstrike-nemesis-connector/" nocase ascii wide
                        $string44 = /\/crack_list\/client_wordlists\.py/ nocase ascii wide
                        $string45 = /\/crack_list\/cracklist_api\.py/ nocase ascii wide
                        $string46 = /\/crack_list\/dictionary\.py/ nocase ascii wide
                        $string47 = /\/crack_list\/wordlist\.py/ nocase ascii wide
                        $string48 = /\/custom_crack_list\.txt/ nocase ascii wide
                        $string49 = /\/dpapi_domain_backupkey\.py/ nocase ascii wide
                        $string50 = /\/dpapi_masterkey\.py/ nocase ascii wide
                        $string51 = /\/DPAPImk2john\.py/ nocase ascii wide
                        $string52 = /\/john_the_ripper_cracker\.py/ nocase ascii wide
                        $string53 = /\/Nemesis\.git/ nocase ascii wide
                        $string54 = /\/nemesis_connector\.py/ nocase ascii wide
                        $string55 = /\/nemesis_db\.py/ nocase ascii wide
                        $string56 = /\/nemesis_reg_collect_parser\.py/ nocase ascii wide
                        $string57 = /\/nemesis\-cli\.py/ nocase ascii wide
                        $string58 = /\/office2john\.py/ nocase ascii wide
                        $string59 = "/opt/cobaltstrike-nemesis"
                        $string60 = /\/passwd\.py/
                        $string61 = /\/password_cracker\.py/ nocase ascii wide
                        $string62 = /\/passwordcracker\.Dockerfile/ nocase ascii wide
                        $string63 = "/passwordcracker/" nocase ascii wide
                        $string64 = /\/pdf2john\.py/ nocase ascii wide
                        $string65 = /\/reg_hive_sam\.py/ nocase ascii wide
                        $string66 = /\/reg_hive_security\.py/ nocase ascii wide
                        $string67 = /\/reg_hive_system\.py/ nocase ascii wide
                        $string68 = /\/seatbelt_json\.py/ nocase ascii wide
                        $string69 = /\/secretsdump\.py/ nocase ascii wide
                        $string70 = /\/sliver_pb2\.py/ nocase ascii wide
                        $string71 = /\/sliver_pb2_grpc\.py/ nocase ascii wide
                        $string72 = /\/submit_to_nemesis\.py/ nocase ascii wide
                        $string73 = /\/submit_to_nemesis\.sh/ nocase ascii wide
                        $string74 = /\/submit_to_nemesis\.yaml/ nocase ascii wide
                        $string75 = /\/wordlists\/top_10000\.txt/ nocase ascii wide
                        $string76 = /\/wordlists\/top_100000\.txt/ nocase ascii wide
                        $string77 = ":8080/yara/file" nocase ascii wide
                        $string78 = /\\Seatbelt\.exe/ nocase ascii wide
                        $string79 = "AWS_BUCKET=nemesis-test" nocase ascii wide
                        $string80 = "AWS_KMS_KEY_ALIAS=nemesis-dev" nocase ascii wide
                        $string81 = "class Plugin::Nemesis < Msf::Plugin" nocase ascii wide
                        $string82 = "cobaltstrike-nemesis-connector" nocase ascii wide
                        $string83 = /create_nemesis_db\(/ nocase ascii wide
                        $string84 = /create_nemesis_db_pool\(/ nocase ascii wide
                        $string85 = /def\snemesis_post_data\(/ nocase ascii wide
                        $string86 = "export NEMESIS_BASE_URL" nocase ascii wide
                        $string87 = "export NEMESIS_CREDS" nocase ascii wide
                        $string88 = /file_parsers\/group_policy_preferences\.py/ nocase ascii wide
                        $string89 = /getLogger\(\\"NemesisConnector\\"\)/ nocase ascii wide
                        $string90 = "http://nemesis/file" nocase ascii wide
                        $string91 = "http://nemesis/yara" nocase ascii wide
                        $string92 = /http\:\/\/nemesis\-es\-http\.default\.svc\.cluster\.local\:9200/ nocase ascii wide
                        $string93 = "http://nemesis-es-internal-http:9200" nocase ascii wide
                        $string94 = /http\:\/\/nemesis\-kb\-http\.default\.svc\.cluster\.local\:5601/ nocase ascii wide
                        $string95 = "http://nemesis-kb-http:5601" nocase ascii wide
                        $string96 = /https\:\/\/nemesis\..{0,100}\.com\/api\// nocase ascii wide
                        $string97 = /logging\.getLogger\(\\"nemesis\\"\)/ nocase ascii wide
                        $string98 = /modules\/nemesis\.rb/ nocase ascii wide
                        $string99 = "Nemesis frontend HTTP server endpoint" nocase ascii wide
                        $string100 = "nemesis:Qwerty12345@" nocase ascii wide
                        $string101 = /nemesis\@nemesis\.com/ nocase ascii wide
                        $string102 = /nemesis\@nemesis\.local/ nocase ascii wide
                        $string103 = "NEMESIS_API_URL" nocase ascii wide
                        $string104 = "NEMESIS_HTTP_SERVER " nocase ascii wide
                        $string105 = /nemesis_post_file\(/ nocase ascii wide
                        $string106 = "nemesis-rabbitmq-discovery" nocase ascii wide
                        $string107 = /nemesis\-rabbitmq\-discovery\.default\.svc\.cluster\.local/ nocase ascii wide
                        $string108 = "NemesisRabbitMQProducer" nocase ascii wide
                        $string109 = /plugins\/nemesis\.rb/ nocase ascii wide
                        $string110 = "sample_files/passwd" nocase ascii wide
                        $string111 = /Seatbelt\.Commands\.Windows/ nocase ascii wide
                        $string112 = "skaffold run -m nemesis " nocase ascii wide
                        $string113 = "SpecterOps/Nemesis" nocase ascii wide
                        $string114 = /Staring\sNemesis\sBot\.\sTeamserver/ nocase ascii wide
                        $string115 = /webapi\/nemesis_api\.py/ nocase ascii wide
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