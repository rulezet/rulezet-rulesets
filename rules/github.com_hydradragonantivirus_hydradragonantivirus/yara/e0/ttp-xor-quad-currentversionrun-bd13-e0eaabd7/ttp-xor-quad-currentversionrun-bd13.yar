rule TTP_XOR_QUAD_CurrentVersionRun_bd13 {
  strings:
    $key_bd13 = { ee 7c [2] ca 72 [2] e1 5e [2] cf 7c [2] db 67 [2] d4 7d [2] ca 60 [2] c8 61 [2] d3 67 [2] cf 60 [2] d3 4f }

  condition:
    any of them
}