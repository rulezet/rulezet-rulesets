rule TTP_XOR_QUAD_CurrentVersionRun_cf38 {
  strings:
    $key_cf38 = { 9c 57 [2] b8 59 [2] 93 75 [2] bd 57 [2] a9 4c [2] a6 56 [2] b8 4b [2] ba 4a [2] a1 4c [2] bd 4b [2] a1 64 }

  condition:
    any of them
}