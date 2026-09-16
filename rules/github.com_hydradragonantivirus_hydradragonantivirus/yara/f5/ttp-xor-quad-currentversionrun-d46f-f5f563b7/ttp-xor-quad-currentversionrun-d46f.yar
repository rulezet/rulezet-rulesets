rule TTP_XOR_QUAD_CurrentVersionRun_d46f {
  strings:
    $key_d46f = { 87 00 [2] a3 0e [2] 88 22 [2] a6 00 [2] b2 1b [2] bd 01 [2] a3 1c [2] a1 1d [2] ba 1b [2] a6 1c [2] ba 33 }

  condition:
    any of them
}