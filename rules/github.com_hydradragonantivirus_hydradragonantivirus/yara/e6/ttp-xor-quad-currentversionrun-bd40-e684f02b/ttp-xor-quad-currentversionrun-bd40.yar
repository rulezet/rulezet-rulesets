rule TTP_XOR_QUAD_CurrentVersionRun_bd40 {
  strings:
    $key_bd40 = { ee 2f [2] ca 21 [2] e1 0d [2] cf 2f [2] db 34 [2] d4 2e [2] ca 33 [2] c8 32 [2] d3 34 [2] cf 33 [2] d3 1c }

  condition:
    any of them
}