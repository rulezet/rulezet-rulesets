rule TTP_XOR_QUAD_CurrentVersionRun_d654 {
  strings:
    $key_d654 = { 85 3b [2] a1 35 [2] 8a 19 [2] a4 3b [2] b0 20 [2] bf 3a [2] a1 27 [2] a3 26 [2] b8 20 [2] a4 27 [2] b8 08 }

  condition:
    any of them
}