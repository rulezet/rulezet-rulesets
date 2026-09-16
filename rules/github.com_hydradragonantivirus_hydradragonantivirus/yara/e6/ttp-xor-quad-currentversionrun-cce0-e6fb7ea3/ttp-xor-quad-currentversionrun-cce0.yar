rule TTP_XOR_QUAD_CurrentVersionRun_cce0 {
  strings:
    $key_cce0 = { 9f 8f [2] bb 81 [2] 90 ad [2] be 8f [2] aa 94 [2] a5 8e [2] bb 93 [2] b9 92 [2] a2 94 [2] be 93 [2] a2 bc }

  condition:
    any of them
}