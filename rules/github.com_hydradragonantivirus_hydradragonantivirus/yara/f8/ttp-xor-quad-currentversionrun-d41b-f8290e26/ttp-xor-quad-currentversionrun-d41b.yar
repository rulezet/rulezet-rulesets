rule TTP_XOR_QUAD_CurrentVersionRun_d41b {
  strings:
    $key_d41b = { 87 74 [2] a3 7a [2] 88 56 [2] a6 74 [2] b2 6f [2] bd 75 [2] a3 68 [2] a1 69 [2] ba 6f [2] a6 68 [2] ba 47 }

  condition:
    any of them
}