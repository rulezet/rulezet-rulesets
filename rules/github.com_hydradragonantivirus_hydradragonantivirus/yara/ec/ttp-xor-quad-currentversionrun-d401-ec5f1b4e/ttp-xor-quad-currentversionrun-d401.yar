rule TTP_XOR_QUAD_CurrentVersionRun_d401 {
  strings:
    $key_d401 = { 87 6e [2] a3 60 [2] 88 4c [2] a6 6e [2] b2 75 [2] bd 6f [2] a3 72 [2] a1 73 [2] ba 75 [2] a6 72 [2] ba 5d }

  condition:
    any of them
}