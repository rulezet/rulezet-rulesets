rule TTP_XOR_QUAD_CurrentVersionRun_bd69 {
  strings:
    $key_bd69 = { ee 06 [2] ca 08 [2] e1 24 [2] cf 06 [2] db 1d [2] d4 07 [2] ca 1a [2] c8 1b [2] d3 1d [2] cf 1a [2] d3 35 }

  condition:
    any of them
}