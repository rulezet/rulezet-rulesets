rule TTP_XOR_QUAD_CurrentVersionRun_d438 {
  strings:
    $key_d438 = { 87 57 [2] a3 59 [2] 88 75 [2] a6 57 [2] b2 4c [2] bd 56 [2] a3 4b [2] a1 4a [2] ba 4c [2] a6 4b [2] ba 64 }

  condition:
    any of them
}