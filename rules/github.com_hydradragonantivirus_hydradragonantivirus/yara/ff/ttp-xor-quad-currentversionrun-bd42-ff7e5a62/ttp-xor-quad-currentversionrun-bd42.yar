rule TTP_XOR_QUAD_CurrentVersionRun_bd42 {
  strings:
    $key_bd42 = { ee 2d [2] ca 23 [2] e1 0f [2] cf 2d [2] db 36 [2] d4 2c [2] ca 31 [2] c8 30 [2] d3 36 [2] cf 31 [2] d3 1e }

  condition:
    any of them
}