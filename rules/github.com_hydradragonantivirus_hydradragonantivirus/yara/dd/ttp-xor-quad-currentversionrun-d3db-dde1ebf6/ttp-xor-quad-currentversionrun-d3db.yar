rule TTP_XOR_QUAD_CurrentVersionRun_d3db {
  strings:
    $key_d3db = { 80 b4 [2] a4 ba [2] 8f 96 [2] a1 b4 [2] b5 af [2] ba b5 [2] a4 a8 [2] a6 a9 [2] bd af [2] a1 a8 [2] bd 87 }

  condition:
    any of them
}