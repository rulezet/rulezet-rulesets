rule TTP_XOR_QUAD_CurrentVersionRun_d433 {
  strings:
    $key_d433 = { 87 5c [2] a3 52 [2] 88 7e [2] a6 5c [2] b2 47 [2] bd 5d [2] a3 40 [2] a1 41 [2] ba 47 [2] a6 40 [2] ba 6f }

  condition:
    any of them
}