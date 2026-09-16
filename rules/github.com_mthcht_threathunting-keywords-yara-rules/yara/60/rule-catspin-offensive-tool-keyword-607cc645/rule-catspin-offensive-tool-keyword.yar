rule rule_catspin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'catspin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catspin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_catspin_offensive_tool_keyword = /\scatspin\.sh\s/
                        $string2_catspin_offensive_tool_keyword = /\sfile\:\/\/catspin\.yaml\s/ nocase ascii wide
                        $string3_catspin_offensive_tool_keyword = " --stack-name catspin " nocase ascii wide
                        $string4_catspin_offensive_tool_keyword = /\/catspin\.git/ nocase ascii wide
                        $string5_catspin_offensive_tool_keyword = "/catspin-main/" nocase ascii wide
                        $string6_catspin_offensive_tool_keyword = /\/execute\-api\.eu\-central\-1\.amazonaws\.com\/catspin_deployed/ nocase ascii wide
                        $string7_catspin_offensive_tool_keyword = /\[\+\]\sUse\s\-info\sto\sget\sstack\sstatus\sand\sthe\senpoint\surl\sof\scatspin/ nocase ascii wide
                        $string8_catspin_offensive_tool_keyword = /\[\+\]\sYou\sspin\smy\sgato\sround\sright\sround\s\?/ nocase ascii wide
                        $string9_catspin_offensive_tool_keyword = /\\catspin\-main\\/ nocase ascii wide
                        $string10_catspin_offensive_tool_keyword = /catspin\.sh\shttp/
                        $string11_catspin_offensive_tool_keyword = /catspin\.sh\s\-info/
                        $string12_catspin_offensive_tool_keyword = /catspin\.sh\s\-kill/
                        $string13_catspin_offensive_tool_keyword = /catspin\.sh\s\-run\s/
                        $string14_catspin_offensive_tool_keyword = /catspin_for_readme\.mp4/ nocase ascii wide
                        $string15_catspin_offensive_tool_keyword = /catspin_poc\.mp4/ nocase ascii wide
                        $string16_catspin_offensive_tool_keyword = /catspin_poc_final\.mp4/ nocase ascii wide
                        $string17_catspin_offensive_tool_keyword = "rootcathacking/catspin" nocase ascii wide
                        $string18_catspin_offensive_tool_keyword = "Spins up catspin using Api Gateway proxy" nocase ascii wide

    condition:
        any of them
}