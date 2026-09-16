rule TTP_XOR_QUAD_CurrentVersionRun_d47e {
  strings:
    $key_d47e = { 87 11 [2] a3 1f [2] 88 33 [2] a6 11 [2] b2 0a [2] bd 10 [2] a3 0d [2] a1 0c [2] ba 0a [2] a6 0d [2] ba 22 }

  condition:
    any of them
}