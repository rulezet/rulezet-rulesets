rule TTP_XOR_QUAD_CurrentVersionRun_d32f {
  strings:
    $key_d32f = { 80 40 [2] a4 4e [2] 8f 62 [2] a1 40 [2] b5 5b [2] ba 41 [2] a4 5c [2] a6 5d [2] bd 5b [2] a1 5c [2] bd 73 }

  condition:
    any of them
}