rule TTP_XOR_QUAD_CurrentVersionRun_cc9c {
  strings:
    $key_cc9c = { 9f f3 [2] bb fd [2] 90 d1 [2] be f3 [2] aa e8 [2] a5 f2 [2] bb ef [2] b9 ee [2] a2 e8 [2] be ef [2] a2 c0 }

  condition:
    any of them
}