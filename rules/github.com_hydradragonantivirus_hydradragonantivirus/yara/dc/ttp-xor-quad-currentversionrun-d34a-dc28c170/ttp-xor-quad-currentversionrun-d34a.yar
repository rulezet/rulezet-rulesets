rule TTP_XOR_QUAD_CurrentVersionRun_d34a {
  strings:
    $key_d34a = { 80 25 [2] a4 2b [2] 8f 07 [2] a1 25 [2] b5 3e [2] ba 24 [2] a4 39 [2] a6 38 [2] bd 3e [2] a1 39 [2] bd 16 }

  condition:
    any of them
}