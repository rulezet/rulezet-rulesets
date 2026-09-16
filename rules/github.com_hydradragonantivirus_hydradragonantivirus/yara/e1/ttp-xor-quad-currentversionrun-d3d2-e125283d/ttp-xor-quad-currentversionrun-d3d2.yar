rule TTP_XOR_QUAD_CurrentVersionRun_d3d2 {
  strings:
    $key_d3d2 = { 80 bd [2] a4 b3 [2] 8f 9f [2] a1 bd [2] b5 a6 [2] ba bc [2] a4 a1 [2] a6 a0 [2] bd a6 [2] a1 a1 [2] bd 8e }

  condition:
    any of them
}