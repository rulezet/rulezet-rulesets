rule TTP_XOR_QUAD_CurrentVersionRun_d3eb {
  strings:
    $key_d3eb = { 80 84 [2] a4 8a [2] 8f a6 [2] a1 84 [2] b5 9f [2] ba 85 [2] a4 98 [2] a6 99 [2] bd 9f [2] a1 98 [2] bd b7 }

  condition:
    any of them
}