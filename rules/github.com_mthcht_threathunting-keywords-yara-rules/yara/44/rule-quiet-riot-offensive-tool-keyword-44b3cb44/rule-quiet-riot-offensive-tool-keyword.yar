rule rule_quiet_riot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'quiet-riot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "quiet-riot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_quiet_riot_offensive_tool_keyword = /\secrprivenum\.py/ nocase ascii wide
                        $string2_quiet_riot_offensive_tool_keyword = /\secrpubenum\.py/ nocase ascii wide
                        $string3_quiet_riot_offensive_tool_keyword = /\siamassumeroleenum\.py/ nocase ascii wide
                        $string4_quiet_riot_offensive_tool_keyword = /\slambdaenum\.py/ nocase ascii wide
                        $string5_quiet_riot_offensive_tool_keyword = /\sloadbalancer\.py/ nocase ascii wide
                        $string6_quiet_riot_offensive_tool_keyword = /\ss3aclenum\.py/ nocase ascii wide
                        $string7_quiet_riot_offensive_tool_keyword = /\ss3enum\.py/ nocase ascii wide
                        $string8_quiet_riot_offensive_tool_keyword = /\ssecretsmanagerenum\.py/ nocase ascii wide
                        $string9_quiet_riot_offensive_tool_keyword = /\ssnsenum\.py/ nocase ascii wide
                        $string10_quiet_riot_offensive_tool_keyword = /\/ecrprivenum\.py/ nocase ascii wide
                        $string11_quiet_riot_offensive_tool_keyword = /\/ecrpubenum\.py/ nocase ascii wide
                        $string12_quiet_riot_offensive_tool_keyword = /\/iamassumeroleenum\.py/ nocase ascii wide
                        $string13_quiet_riot_offensive_tool_keyword = /\/lambdaenum\.py/ nocase ascii wide
                        $string14_quiet_riot_offensive_tool_keyword = /\/loadbalancer\.py/ nocase ascii wide
                        $string15_quiet_riot_offensive_tool_keyword = /\/quiet\-riot\.git/ nocase ascii wide
                        $string16_quiet_riot_offensive_tool_keyword = /\/s3aclenum\.py/ nocase ascii wide
                        $string17_quiet_riot_offensive_tool_keyword = /\/s3enum\.py/ nocase ascii wide
                        $string18_quiet_riot_offensive_tool_keyword = /\/secretsmanagerenum\.py/ nocase ascii wide
                        $string19_quiet_riot_offensive_tool_keyword = /\/snsenum\.py/ nocase ascii wide
                        $string20_quiet_riot_offensive_tool_keyword = /\/wordlists\/combined_male_names\.txt/
                        $string21_quiet_riot_offensive_tool_keyword = /\/wordlists\/familynames\-usa\-top1000\.txt/
                        $string22_quiet_riot_offensive_tool_keyword = /\/wordlists\/femalenames\-usa\-top1000\.txt/
                        $string23_quiet_riot_offensive_tool_keyword = /\/wordlists\/malenames\-usa\-top1000\.txt/
                        $string24_quiet_riot_offensive_tool_keyword = /\/wordlists\/names_quit_riot\.txt/
                        $string25_quiet_riot_offensive_tool_keyword = /\\ecrprivenum\.py/ nocase ascii wide
                        $string26_quiet_riot_offensive_tool_keyword = /\\ecrpubenum\.py/ nocase ascii wide
                        $string27_quiet_riot_offensive_tool_keyword = /\\iamassumeroleenum\.py/ nocase ascii wide
                        $string28_quiet_riot_offensive_tool_keyword = /\\lambdaenum\.py/ nocase ascii wide
                        $string29_quiet_riot_offensive_tool_keyword = /\\loadbalancer\.py/ nocase ascii wide
                        $string30_quiet_riot_offensive_tool_keyword = /\\quiet\-riot\-main/ nocase ascii wide
                        $string31_quiet_riot_offensive_tool_keyword = /\\s3aclenum\.py/ nocase ascii wide
                        $string32_quiet_riot_offensive_tool_keyword = /\\s3enum\.py/ nocase ascii wide
                        $string33_quiet_riot_offensive_tool_keyword = /\\secretsmanagerenum\.py/ nocase ascii wide
                        $string34_quiet_riot_offensive_tool_keyword = /\\snsenum\.py/ nocase ascii wide
                        $string35_quiet_riot_offensive_tool_keyword = "1f4fc2020e9da18d8783fe9e98b702229756849eb1ef87ee199a94c8ab123f10" nocase ascii wide
                        $string36_quiet_riot_offensive_tool_keyword = "6aa39b4578eae70ad9e80df833b4633a5e78eda7b75b071d14f0a3befdf81223" nocase ascii wide
                        $string37_quiet_riot_offensive_tool_keyword = "75d5f38d2dd472c4d54999cf9b023c92ccb2f5806e78d610325707cb2b8aaa2f" nocase ascii wide
                        $string38_quiet_riot_offensive_tool_keyword = "7cc0f7c80a3b90b1fed9a972ec241328cbc47edd1eede88bcf24933cc55c0e12" nocase ascii wide
                        $string39_quiet_riot_offensive_tool_keyword = "b22850c4a39e5abf07c8e91b943cd477f31a21dc6942801e58d756782cfbc095" nocase ascii wide
                        $string40_quiet_riot_offensive_tool_keyword = "ca6a84b59ef6e40ee3657dd79a54706818d66345725434ade357898aa6722f62" nocase ascii wide
                        $string41_quiet_riot_offensive_tool_keyword = "d75e6210055b8ace4fb94f7108604081c957b97ce17772efd58d7ff845589ce0" nocase ascii wide
                        $string42_quiet_riot_offensive_tool_keyword = "e5f826920a0effa33441079ae4eb87f7dc31534bb6577ba322f13c7d838d5b17" nocase ascii wide
                        $string43_quiet_riot_offensive_tool_keyword = "f2f1896de3273d47b9d6831b9ac66c1a8fbbde28eb433bef65495ffcb81c9105" nocase ascii wide
                        $string44_quiet_riot_offensive_tool_keyword = /from\s\.enumeration\simport\secrprivenum/ nocase ascii wide
                        $string45_quiet_riot_offensive_tool_keyword = /from\s\.enumeration\simport\secrpubenum/ nocase ascii wide
                        $string46_quiet_riot_offensive_tool_keyword = /from\s\.enumeration\simport\sloadbalancer\sas\sloadbalancer/ nocase ascii wide
                        $string47_quiet_riot_offensive_tool_keyword = /from\s\.enumeration\simport\srand_id_generator\sas\srand_id_generator/ nocase ascii wide
                        $string48_quiet_riot_offensive_tool_keyword = /from\s\.enumeration\simport\ss3aclenum\sas\ss3aclenum/ nocase ascii wide
                        $string49_quiet_riot_offensive_tool_keyword = /from\s\.enumeration\simport\ssnsenum/ nocase ascii wide
                        $string50_quiet_riot_offensive_tool_keyword = "pip install quiet-riot" nocase ascii wide
                        $string51_quiet_riot_offensive_tool_keyword = "Quiet Riot discovered one valid e-mail account" nocase ascii wide
                        $string52_quiet_riot_offensive_tool_keyword = "Quiet Riot discovered one valid login account" nocase ascii wide
                        $string53_quiet_riot_offensive_tool_keyword = "quiet_riot --scan_type" nocase ascii wide
                        $string54_quiet_riot_offensive_tool_keyword = "righteousgambit/quiet-riot" nocase ascii wide

    condition:
        any of them
}