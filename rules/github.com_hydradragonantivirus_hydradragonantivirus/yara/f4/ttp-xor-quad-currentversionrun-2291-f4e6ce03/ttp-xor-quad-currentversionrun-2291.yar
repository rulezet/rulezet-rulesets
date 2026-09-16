rule TTP_XOR_QUAD_CurrentVersionRun_2291 {
  strings:
    $key_2291 = { 71 fe [2] 55 f0 [2] 7e dc [2] 50 fe [2] 44 e5 [2] 4b ff [2] 55 e2 [2] 57 e3 [2] 4c e5 [2] 50 e2 [2] 4c cd }

  condition:
    any of them
}