rule TTP_XOR_QUAD_CurrentVersionRun_d416 {
  strings:
    $key_d416 = { 87 79 [2] a3 77 [2] 88 5b [2] a6 79 [2] b2 62 [2] bd 78 [2] a3 65 [2] a1 64 [2] ba 62 [2] a6 65 [2] ba 4a }

  condition:
    any of them
}