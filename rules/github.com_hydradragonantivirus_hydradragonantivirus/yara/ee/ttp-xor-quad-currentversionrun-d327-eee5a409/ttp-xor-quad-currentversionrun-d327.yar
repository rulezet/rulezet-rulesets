rule TTP_XOR_QUAD_CurrentVersionRun_d327 {
  strings:
    $key_d327 = { 80 48 [2] a4 46 [2] 8f 6a [2] a1 48 [2] b5 53 [2] ba 49 [2] a4 54 [2] a6 55 [2] bd 53 [2] a1 54 [2] bd 7b }

  condition:
    any of them
}