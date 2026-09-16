rule TTP_XOR_QUAD_CurrentVersionRun_d45d {
  strings:
    $key_d45d = { 87 32 [2] a3 3c [2] 88 10 [2] a6 32 [2] b2 29 [2] bd 33 [2] a3 2e [2] a1 2f [2] ba 29 [2] a6 2e [2] ba 01 }

  condition:
    any of them
}