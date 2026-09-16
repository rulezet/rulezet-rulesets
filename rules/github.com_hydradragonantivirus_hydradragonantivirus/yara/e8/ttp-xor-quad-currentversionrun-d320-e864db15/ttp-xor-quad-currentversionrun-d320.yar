rule TTP_XOR_QUAD_CurrentVersionRun_d320 {
  strings:
    $key_d320 = { 80 4f [2] a4 41 [2] 8f 6d [2] a1 4f [2] b5 54 [2] ba 4e [2] a4 53 [2] a6 52 [2] bd 54 [2] a1 53 [2] bd 7c }

  condition:
    any of them
}