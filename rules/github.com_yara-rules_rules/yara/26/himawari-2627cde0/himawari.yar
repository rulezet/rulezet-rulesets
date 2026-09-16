rule Himawari {
          meta:
            description = "detect Himawari(a variant of RedLeaves) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
            hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

          strings:
            $h1 = "himawariA"
            $h2 = "himawariB"
            $h3 = "HimawariDemo"

          condition: all of them
}