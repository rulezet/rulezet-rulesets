rule TTP_XOR_QUAD_CurrentVersionRun_c829 {
  strings:
    $key_c829 = { 9b 46 [2] bf 48 [2] 94 64 [2] ba 46 [2] ae 5d [2] a1 47 [2] bf 5a [2] bd 5b [2] a6 5d [2] ba 5a [2] a6 75 }

  condition:
    any of them
}