rule TTP_XOR_QUAD_CurrentVersionRun_d31b {
  strings:
    $key_d31b = { 80 74 [2] a4 7a [2] 8f 56 [2] a1 74 [2] b5 6f [2] ba 75 [2] a4 68 [2] a6 69 [2] bd 6f [2] a1 68 [2] bd 47 }

  condition:
    any of them
}