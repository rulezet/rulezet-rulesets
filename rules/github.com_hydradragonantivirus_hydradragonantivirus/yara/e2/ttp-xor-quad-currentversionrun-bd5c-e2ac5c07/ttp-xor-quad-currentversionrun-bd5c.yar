rule TTP_XOR_QUAD_CurrentVersionRun_bd5c {
  strings:
    $key_bd5c = { ee 33 [2] ca 3d [2] e1 11 [2] cf 33 [2] db 28 [2] d4 32 [2] ca 2f [2] c8 2e [2] d3 28 [2] cf 2f [2] d3 00 }

  condition:
    any of them
}