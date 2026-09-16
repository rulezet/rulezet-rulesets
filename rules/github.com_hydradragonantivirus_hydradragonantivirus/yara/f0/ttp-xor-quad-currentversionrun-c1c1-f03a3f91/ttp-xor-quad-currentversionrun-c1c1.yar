rule TTP_XOR_QUAD_CurrentVersionRun_c1c1 {
  strings:
    $key_c1c1 = { 92 ae [2] b6 a0 [2] 9d 8c [2] b3 ae [2] a7 b5 [2] a8 af [2] b6 b2 [2] b4 b3 [2] af b5 [2] b3 b2 [2] af 9d }

  condition:
    any of them
}