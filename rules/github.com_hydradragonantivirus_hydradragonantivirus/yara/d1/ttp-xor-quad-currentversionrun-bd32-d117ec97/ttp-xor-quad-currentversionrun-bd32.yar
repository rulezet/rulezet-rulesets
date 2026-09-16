rule TTP_XOR_QUAD_CurrentVersionRun_bd32 {
  strings:
    $key_bd32 = { ee 5d [2] ca 53 [2] e1 7f [2] cf 5d [2] db 46 [2] d4 5c [2] ca 41 [2] c8 40 [2] d3 46 [2] cf 41 [2] d3 6e }

  condition:
    any of them
}