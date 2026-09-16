rule TTP_XOR_QUAD_CurrentVersionRun_bd6a {
  strings:
    $key_bd6a = { ee 05 [2] ca 0b [2] e1 27 [2] cf 05 [2] db 1e [2] d4 04 [2] ca 19 [2] c8 18 [2] d3 1e [2] cf 19 [2] d3 36 }

  condition:
    any of them
}