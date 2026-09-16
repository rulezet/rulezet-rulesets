rule TTP_XOR_QUAD_CurrentVersionRun_bd11 {
  strings:
    $key_bd11 = { ee 7e [2] ca 70 [2] e1 5c [2] cf 7e [2] db 65 [2] d4 7f [2] ca 62 [2] c8 63 [2] d3 65 [2] cf 62 [2] d3 4d }

  condition:
    any of them
}