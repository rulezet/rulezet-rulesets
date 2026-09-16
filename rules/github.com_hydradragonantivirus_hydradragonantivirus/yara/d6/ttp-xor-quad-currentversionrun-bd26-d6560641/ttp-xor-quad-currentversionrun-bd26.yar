rule TTP_XOR_QUAD_CurrentVersionRun_bd26 {
  strings:
    $key_bd26 = { ee 49 [2] ca 47 [2] e1 6b [2] cf 49 [2] db 52 [2] d4 48 [2] ca 55 [2] c8 54 [2] d3 52 [2] cf 55 [2] d3 7a }

  condition:
    any of them
}