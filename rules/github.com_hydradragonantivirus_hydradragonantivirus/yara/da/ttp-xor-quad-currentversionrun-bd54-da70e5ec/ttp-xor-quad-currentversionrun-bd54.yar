rule TTP_XOR_QUAD_CurrentVersionRun_bd54 {
  strings:
    $key_bd54 = { ee 3b [2] ca 35 [2] e1 19 [2] cf 3b [2] db 20 [2] d4 3a [2] ca 27 [2] c8 26 [2] d3 20 [2] cf 27 [2] d3 08 }

  condition:
    any of them
}