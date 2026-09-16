rule TTP_XOR_QUAD_CurrentVersionRun_bd44 {
  strings:
    $key_bd44 = { ee 2b [2] ca 25 [2] e1 09 [2] cf 2b [2] db 30 [2] d4 2a [2] ca 37 [2] c8 36 [2] d3 30 [2] cf 37 [2] d3 18 }

  condition:
    any of them
}