rule TTP_XOR_QUAD_CurrentVersionRun_d36c {
  strings:
    $key_d36c = { 80 03 [2] a4 0d [2] 8f 21 [2] a1 03 [2] b5 18 [2] ba 02 [2] a4 1f [2] a6 1e [2] bd 18 [2] a1 1f [2] bd 30 }

  condition:
    any of them
}