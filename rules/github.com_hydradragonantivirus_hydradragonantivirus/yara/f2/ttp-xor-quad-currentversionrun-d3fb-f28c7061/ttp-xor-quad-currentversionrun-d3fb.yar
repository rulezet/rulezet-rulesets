rule TTP_XOR_QUAD_CurrentVersionRun_d3fb {
  strings:
    $key_d3fb = { 80 94 [2] a4 9a [2] 8f b6 [2] a1 94 [2] b5 8f [2] ba 95 [2] a4 88 [2] a6 89 [2] bd 8f [2] a1 88 [2] bd a7 }

  condition:
    any of them
}