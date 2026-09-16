rule TTP_XOR_QUAD_CurrentVersionRun_dfdd {
  strings:
    $key_dfdd = { 8c b2 [2] a8 bc [2] 83 90 [2] ad b2 [2] b9 a9 [2] b6 b3 [2] a8 ae [2] aa af [2] b1 a9 [2] ad ae [2] b1 81 }

  condition:
    any of them
}