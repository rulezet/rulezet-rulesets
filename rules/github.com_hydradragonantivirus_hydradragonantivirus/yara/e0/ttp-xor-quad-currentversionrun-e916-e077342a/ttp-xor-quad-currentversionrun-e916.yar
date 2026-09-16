rule TTP_XOR_QUAD_CurrentVersionRun_e916 {
  strings:
    $key_e916 = { ba 79 [2] 9e 77 [2] b5 5b [2] 9b 79 [2] 8f 62 [2] 80 78 [2] 9e 65 [2] 9c 64 [2] 87 62 [2] 9b 65 [2] 87 4a }

  condition:
    any of them
}