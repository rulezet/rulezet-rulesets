rule Emotet {
          meta:
            description = "detect Emotet in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v4a = { BB 00 C3 4C 84 }
            $v4b = { B8 00 C3 CC 84 }
            $v5a = { 69 01 6D 4E C6 41 05 39 30 00 00 }
            $v5b = { 6D 4E C6 41 33 D2 81 C1 39 30 00 00 }

          condition: ($v4a and $v4b) or $v5a or $v5b
}