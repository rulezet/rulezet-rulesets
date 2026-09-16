rule TTP_XOR_QUAD_CurrentVersionRun_bd41 {
  strings:
    $key_bd41 = { ee 2e [2] ca 20 [2] e1 0c [2] cf 2e [2] db 35 [2] d4 2f [2] ca 32 [2] c8 33 [2] d3 35 [2] cf 32 [2] d3 1d }

  condition:
    any of them
}