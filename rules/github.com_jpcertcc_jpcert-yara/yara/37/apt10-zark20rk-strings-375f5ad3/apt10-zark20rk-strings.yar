rule APT10_zark20rk_strings {
      meta:
        description = "detect zark20rk(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

      strings:
        $a1 = { C7 ?? ?? 7A 61 72 6B }
        $a2 = { C7 ?? ?? 32 30 72 6B }

      condition: all of them
}