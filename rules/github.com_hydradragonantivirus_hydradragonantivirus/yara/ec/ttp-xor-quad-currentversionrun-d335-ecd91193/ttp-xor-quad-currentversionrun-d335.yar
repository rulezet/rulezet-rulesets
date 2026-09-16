rule TTP_XOR_QUAD_CurrentVersionRun_d335 {
  strings:
    $key_d335 = { 80 5a [2] a4 54 [2] 8f 78 [2] a1 5a [2] b5 41 [2] ba 5b [2] a4 46 [2] a6 47 [2] bd 41 [2] a1 46 [2] bd 69 }

  condition:
    any of them
}