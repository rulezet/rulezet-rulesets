rule TTP_XOR_QUAD_CurrentVersionRun_bd57 {
  strings:
    $key_bd57 = { ee 38 [2] ca 36 [2] e1 1a [2] cf 38 [2] db 23 [2] d4 39 [2] ca 24 [2] c8 25 [2] d3 23 [2] cf 24 [2] d3 0b }

  condition:
    any of them
}