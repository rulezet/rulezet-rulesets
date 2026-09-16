rule TTP_XOR_QUAD_CurrentVersionRun_d3d1 {
  strings:
    $key_d3d1 = { 80 be [2] a4 b0 [2] 8f 9c [2] a1 be [2] b5 a5 [2] ba bf [2] a4 a2 [2] a6 a3 [2] bd a5 [2] a1 a2 [2] bd 8d }

  condition:
    any of them
}