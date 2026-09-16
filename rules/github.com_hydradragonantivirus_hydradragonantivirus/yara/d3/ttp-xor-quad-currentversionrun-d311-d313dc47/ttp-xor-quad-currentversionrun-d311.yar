rule TTP_XOR_QUAD_CurrentVersionRun_d311 {
  strings:
    $key_d311 = { 80 7e [2] a4 70 [2] 8f 5c [2] a1 7e [2] b5 65 [2] ba 7f [2] a4 62 [2] a6 63 [2] bd 65 [2] a1 62 [2] bd 4d }

  condition:
    any of them
}