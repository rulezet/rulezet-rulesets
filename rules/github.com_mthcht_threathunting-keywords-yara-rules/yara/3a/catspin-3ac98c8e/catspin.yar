rule catspin
{
    meta:
        description = "Detection patterns for the tool 'catspin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catspin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scatspin\.sh\s/
                        $string2 = /\sfile\:\/\/catspin\.yaml\s/ nocase ascii wide
                        $string3 = " --stack-name catspin " nocase ascii wide
                        $string4 = /\/catspin\.git/ nocase ascii wide
                        $string5 = "/catspin-main/" nocase ascii wide
                        $string6 = /\/execute\-api\.eu\-central\-1\.amazonaws\.com\/catspin_deployed/ nocase ascii wide
                        $string7 = /\[\+\]\sUse\s\-info\sto\sget\sstack\sstatus\sand\sthe\senpoint\surl\sof\scatspin/ nocase ascii wide
                        $string8 = /\[\+\]\sYou\sspin\smy\sgato\sround\sright\sround\s\?/ nocase ascii wide
                        $string9 = /\\catspin\-main\\/ nocase ascii wide
                        $string10 = /catspin\.sh\shttp/
                        $string11 = /catspin\.sh\s\-info/
                        $string12 = /catspin\.sh\s\-kill/
                        $string13 = /catspin\.sh\s\-run\s/
                        $string14 = /catspin_for_readme\.mp4/ nocase ascii wide
                        $string15 = /catspin_poc\.mp4/ nocase ascii wide
                        $string16 = /catspin_poc_final\.mp4/ nocase ascii wide
                        $string17 = "rootcathacking/catspin" nocase ascii wide
                        $string18 = "Spins up catspin using Api Gateway proxy" nocase ascii wide

    condition:
        any of them
}