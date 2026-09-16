rule TTP_XOR_QUAD_CurrentVersionRun_bd9b {
  strings:
    $key_bd9b = { ee f4 [2] ca fa [2] e1 d6 [2] cf f4 [2] db ef [2] d4 f5 [2] ca e8 [2] c8 e9 [2] d3 ef [2] cf e8 [2] d3 c7 }

  condition:
    any of them
}