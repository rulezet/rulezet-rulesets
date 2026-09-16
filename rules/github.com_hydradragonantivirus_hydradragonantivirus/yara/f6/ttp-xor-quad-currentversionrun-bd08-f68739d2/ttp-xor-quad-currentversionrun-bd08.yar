rule TTP_XOR_QUAD_CurrentVersionRun_bd08 {
  strings:
    $key_bd08 = { ee 67 [2] ca 69 [2] e1 45 [2] cf 67 [2] db 7c [2] d4 66 [2] ca 7b [2] c8 7a [2] d3 7c [2] cf 7b [2] d3 54 }

  condition:
    any of them
}