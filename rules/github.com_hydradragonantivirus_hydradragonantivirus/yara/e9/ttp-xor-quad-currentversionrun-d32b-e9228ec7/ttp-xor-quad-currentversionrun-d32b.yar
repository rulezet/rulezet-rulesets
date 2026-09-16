rule TTP_XOR_QUAD_CurrentVersionRun_d32b {
  strings:
    $key_d32b = { 80 44 [2] a4 4a [2] 8f 66 [2] a1 44 [2] b5 5f [2] ba 45 [2] a4 58 [2] a6 59 [2] bd 5f [2] a1 58 [2] bd 77 }

  condition:
    any of them
}