rule TTP_XOR_QUAD_CurrentVersionRun_d445 {
  strings:
    $key_d445 = { 87 2a [2] a3 24 [2] 88 08 [2] a6 2a [2] b2 31 [2] bd 2b [2] a3 36 [2] a1 37 [2] ba 31 [2] a6 36 [2] ba 19 }

  condition:
    any of them
}