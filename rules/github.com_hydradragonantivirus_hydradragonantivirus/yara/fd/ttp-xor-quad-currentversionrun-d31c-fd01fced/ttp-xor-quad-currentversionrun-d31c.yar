rule TTP_XOR_QUAD_CurrentVersionRun_d31c {
  strings:
    $key_d31c = { 80 73 [2] a4 7d [2] 8f 51 [2] a1 73 [2] b5 68 [2] ba 72 [2] a4 6f [2] a6 6e [2] bd 68 [2] a1 6f [2] bd 40 }

  condition:
    any of them
}