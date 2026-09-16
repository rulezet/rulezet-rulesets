rule TTP_XOR_QUAD_CurrentVersionRun_d3c0 {
  strings:
    $key_d3c0 = { 80 af [2] a4 a1 [2] 8f 8d [2] a1 af [2] b5 b4 [2] ba ae [2] a4 b3 [2] a6 b2 [2] bd b4 [2] a1 b3 [2] bd 9c }

  condition:
    any of them
}