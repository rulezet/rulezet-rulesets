rule TTP_XOR_QUAD_CurrentVersionRun_bd52 {
  strings:
    $key_bd52 = { ee 3d [2] ca 33 [2] e1 1f [2] cf 3d [2] db 26 [2] d4 3c [2] ca 21 [2] c8 20 [2] d3 26 [2] cf 21 [2] d3 0e }

  condition:
    any of them
}