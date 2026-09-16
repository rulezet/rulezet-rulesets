rule TTP_XOR_QUAD_CurrentVersionRun_d328 {
  strings:
    $key_d328 = { 80 47 [2] a4 49 [2] 8f 65 [2] a1 47 [2] b5 5c [2] ba 46 [2] a4 5b [2] a6 5a [2] bd 5c [2] a1 5b [2] bd 74 }

  condition:
    any of them
}