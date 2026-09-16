rule TTP_XOR_QUAD_CurrentVersionRun_bd37 {
  strings:
    $key_bd37 = { ee 58 [2] ca 56 [2] e1 7a [2] cf 58 [2] db 43 [2] d4 59 [2] ca 44 [2] c8 45 [2] d3 43 [2] cf 44 [2] d3 6b }

  condition:
    any of them
}