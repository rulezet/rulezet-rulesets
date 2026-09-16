rule TTP_XOR_QUAD_CurrentVersionRun_cf62 {
  strings:
    $key_cf62 = { 9c 0d [2] b8 03 [2] 93 2f [2] bd 0d [2] a9 16 [2] a6 0c [2] b8 11 [2] ba 10 [2] a1 16 [2] bd 11 [2] a1 3e }

  condition:
    any of them
}