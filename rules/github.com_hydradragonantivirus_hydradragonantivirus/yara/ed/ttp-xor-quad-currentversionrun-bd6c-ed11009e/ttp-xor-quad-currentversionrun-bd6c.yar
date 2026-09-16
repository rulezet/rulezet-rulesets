rule TTP_XOR_QUAD_CurrentVersionRun_bd6c {
  strings:
    $key_bd6c = { ee 03 [2] ca 0d [2] e1 21 [2] cf 03 [2] db 18 [2] d4 02 [2] ca 1f [2] c8 1e [2] d3 18 [2] cf 1f [2] d3 30 }

  condition:
    any of them
}