rule TTP_XOR_QUAD_CurrentVersionRun_d4fd {
  strings:
    $key_d4fd = { 87 92 [2] a3 9c [2] 88 b0 [2] a6 92 [2] b2 89 [2] bd 93 [2] a3 8e [2] a1 8f [2] ba 89 [2] a6 8e [2] ba a1 }

  condition:
    any of them
}