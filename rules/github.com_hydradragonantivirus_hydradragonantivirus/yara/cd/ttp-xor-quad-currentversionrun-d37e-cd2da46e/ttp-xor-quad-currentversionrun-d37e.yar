rule TTP_XOR_QUAD_CurrentVersionRun_d37e {
  strings:
    $key_d37e = { 80 11 [2] a4 1f [2] 8f 33 [2] a1 11 [2] b5 0a [2] ba 10 [2] a4 0d [2] a6 0c [2] bd 0a [2] a1 0d [2] bd 22 }

  condition:
    any of them
}