rule TTP_XOR_QUAD_CurrentVersionRun_d462 {
  strings:
    $key_d462 = { 87 0d [2] a3 03 [2] 88 2f [2] a6 0d [2] b2 16 [2] bd 0c [2] a3 11 [2] a1 10 [2] ba 16 [2] a6 11 [2] ba 3e }

  condition:
    any of them
}