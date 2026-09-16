rule xxmm {
          meta:
            description = "detect xxmm in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "setupParameter:"
            $v2 = "loaderParameter:"
            $v3 = "parameter:"

          condition: all of them
}