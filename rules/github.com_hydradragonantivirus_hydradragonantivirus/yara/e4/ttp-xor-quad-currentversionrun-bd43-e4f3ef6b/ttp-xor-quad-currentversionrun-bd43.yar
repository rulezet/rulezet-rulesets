rule TTP_XOR_QUAD_CurrentVersionRun_bd43 {
  strings:
    $key_bd43 = { ee 2c [2] ca 22 [2] e1 0e [2] cf 2c [2] db 37 [2] d4 2d [2] ca 30 [2] c8 31 [2] d3 37 [2] cf 30 [2] d3 1f }

  condition:
    any of them
}