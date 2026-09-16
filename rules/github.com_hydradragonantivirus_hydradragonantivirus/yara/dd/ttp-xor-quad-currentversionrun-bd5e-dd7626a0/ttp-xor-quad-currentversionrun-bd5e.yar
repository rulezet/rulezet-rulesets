rule TTP_XOR_QUAD_CurrentVersionRun_bd5e {
  strings:
    $key_bd5e = { ee 31 [2] ca 3f [2] e1 13 [2] cf 31 [2] db 2a [2] d4 30 [2] ca 2d [2] c8 2c [2] d3 2a [2] cf 2d [2] d3 02 }

  condition:
    any of them
}