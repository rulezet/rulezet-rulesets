rule TTP_XOR_QUAD_CurrentVersionRun_ccdd {
  strings:
    $key_ccdd = { 9f b2 [2] bb bc [2] 90 90 [2] be b2 [2] aa a9 [2] a5 b3 [2] bb ae [2] b9 af [2] a2 a9 [2] be ae [2] a2 81 }

  condition:
    any of them
}