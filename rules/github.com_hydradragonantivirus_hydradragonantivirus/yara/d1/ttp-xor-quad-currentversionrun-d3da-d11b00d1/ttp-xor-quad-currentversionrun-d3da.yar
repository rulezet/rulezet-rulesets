rule TTP_XOR_QUAD_CurrentVersionRun_d3da {
  strings:
    $key_d3da = { 80 b5 [2] a4 bb [2] 8f 97 [2] a1 b5 [2] b5 ae [2] ba b4 [2] a4 a9 [2] a6 a8 [2] bd ae [2] a1 a9 [2] bd 86 }

  condition:
    any of them
}