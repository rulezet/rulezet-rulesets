rule TTP_XOR_QUAD_CurrentVersionRun_bd2e {
  strings:
    $key_bd2e = { ee 41 [2] ca 4f [2] e1 63 [2] cf 41 [2] db 5a [2] d4 40 [2] ca 5d [2] c8 5c [2] d3 5a [2] cf 5d [2] d3 72 }

  condition:
    any of them
}