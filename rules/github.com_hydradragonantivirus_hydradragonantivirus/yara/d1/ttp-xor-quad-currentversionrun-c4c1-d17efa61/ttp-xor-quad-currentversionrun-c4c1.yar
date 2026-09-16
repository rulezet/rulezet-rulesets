rule TTP_XOR_QUAD_CurrentVersionRun_c4c1 {
  strings:
    $key_c4c1 = { 97 ae [2] b3 a0 [2] 98 8c [2] b6 ae [2] a2 b5 [2] ad af [2] b3 b2 [2] b1 b3 [2] aa b5 [2] b6 b2 [2] aa 9d }

  condition:
    any of them
}