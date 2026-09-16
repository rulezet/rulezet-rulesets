rule TTP_XOR_QUAD_CurrentVersionRun_bd61 {
  strings:
    $key_bd61 = { ee 0e [2] ca 00 [2] e1 2c [2] cf 0e [2] db 15 [2] d4 0f [2] ca 12 [2] c8 13 [2] d3 15 [2] cf 12 [2] d3 3d }

  condition:
    any of them
}