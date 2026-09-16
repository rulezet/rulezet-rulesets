rule TTP_XOR_QUAD_CurrentVersionRun_d47a {
  strings:
    $key_d47a = { 87 15 [2] a3 1b [2] 88 37 [2] a6 15 [2] b2 0e [2] bd 14 [2] a3 09 [2] a1 08 [2] ba 0e [2] a6 09 [2] ba 26 }

  condition:
    any of them
}