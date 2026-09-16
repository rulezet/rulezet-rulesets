rule TTP_XOR_QUAD_CurrentVersionRun_fc35 {
  strings:
    $key_fc35 = { af 5a [2] 8b 54 [2] a0 78 [2] 8e 5a [2] 9a 41 [2] 95 5b [2] 8b 46 [2] 89 47 [2] 92 41 [2] 8e 46 [2] 92 69 }

  condition:
    any of them
}