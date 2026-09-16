rule Datper {
          meta:
            description = "detect Datper in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2017/08/detecting-datper-malware-from-proxy-logs.html"

          strings:
            $a1 = { E8 03 00 00 }
            $b1 = "|||"
            $c1 = "Content-Type: application/x-www-form-urlencoded"
            $push7530h64 = { C7 C1 30 75 00 00 }
            $push7530h = { 68 30 75 00 00 }

          condition: $a1 and $b1 and $c1 and ($push7530h64 or $push7530h)
}