rule TTP_XOR_QUAD_CurrentVersionRun_bd86 {
  strings:
    $key_bd86 = { ee e9 [2] ca e7 [2] e1 cb [2] cf e9 [2] db f2 [2] d4 e8 [2] ca f5 [2] c8 f4 [2] d3 f2 [2] cf f5 [2] d3 da }

  condition:
    any of them
}