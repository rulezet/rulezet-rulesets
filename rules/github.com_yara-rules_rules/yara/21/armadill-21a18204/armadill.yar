rule Armadill {
          meta:
            description = "detect Armadill(a variant of RedLeaves) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $a1 = { C7 ?? ?? 41 72 6D 61 }
            $a2 = { C7 ?? ?? 64 69 6C 6C }

          condition: all of them
}