rule TTP_XOR_QUAD_CurrentVersionRun_bd51 {
  strings:
    $key_bd51 = { ee 3e [2] ca 30 [2] e1 1c [2] cf 3e [2] db 25 [2] d4 3f [2] ca 22 [2] c8 23 [2] d3 25 [2] cf 22 [2] d3 0d }

  condition:
    any of them
}