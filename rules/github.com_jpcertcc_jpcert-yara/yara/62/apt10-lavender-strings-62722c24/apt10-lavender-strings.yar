rule APT10_Lavender_strings {
      meta:
        description = "detect Lavender(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

      strings:
        $a1 = { C7 ?? ?? 4C 41 56 45 }
        $a2 = { C7 ?? ?? 4E 44 45 52 }

      condition: all of them
}