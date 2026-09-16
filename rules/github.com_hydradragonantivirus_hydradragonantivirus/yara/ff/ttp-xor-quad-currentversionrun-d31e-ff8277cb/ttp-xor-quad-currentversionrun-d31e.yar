rule TTP_XOR_QUAD_CurrentVersionRun_d31e {
  strings:
    $key_d31e = { 80 71 [2] a4 7f [2] 8f 53 [2] a1 71 [2] b5 6a [2] ba 70 [2] a4 6d [2] a6 6c [2] bd 6a [2] a1 6d [2] bd 42 }

  condition:
    any of them
}