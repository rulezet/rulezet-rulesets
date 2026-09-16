rule TTP_XOR_QUAD_CurrentVersionRun_c84b {
  strings:
    $key_c84b = { 9b 24 [2] bf 2a [2] 94 06 [2] ba 24 [2] ae 3f [2] a1 25 [2] bf 38 [2] bd 39 [2] a6 3f [2] ba 38 [2] a6 17 }

  condition:
    any of them
}