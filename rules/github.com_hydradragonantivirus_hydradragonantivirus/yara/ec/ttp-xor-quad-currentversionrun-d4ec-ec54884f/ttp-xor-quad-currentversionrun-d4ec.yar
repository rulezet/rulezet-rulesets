rule TTP_XOR_QUAD_CurrentVersionRun_d4ec {
  strings:
    $key_d4ec = { 87 83 [2] a3 8d [2] 88 a1 [2] a6 83 [2] b2 98 [2] bd 82 [2] a3 9f [2] a1 9e [2] ba 98 [2] a6 9f [2] ba b0 }

  condition:
    any of them
}