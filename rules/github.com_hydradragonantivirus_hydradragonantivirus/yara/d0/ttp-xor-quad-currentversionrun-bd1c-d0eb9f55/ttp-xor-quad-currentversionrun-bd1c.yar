rule TTP_XOR_QUAD_CurrentVersionRun_bd1c {
  strings:
    $key_bd1c = { ee 73 [2] ca 7d [2] e1 51 [2] cf 73 [2] db 68 [2] d4 72 [2] ca 6f [2] c8 6e [2] d3 68 [2] cf 6f [2] d3 40 }

  condition:
    any of them
}