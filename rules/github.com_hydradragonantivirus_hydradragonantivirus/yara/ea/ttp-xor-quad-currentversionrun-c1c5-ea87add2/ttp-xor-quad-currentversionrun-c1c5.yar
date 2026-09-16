rule TTP_XOR_QUAD_CurrentVersionRun_c1c5 {
  strings:
    $key_c1c5 = { 92 aa [2] b6 a4 [2] 9d 88 [2] b3 aa [2] a7 b1 [2] a8 ab [2] b6 b6 [2] b4 b7 [2] af b1 [2] b3 b6 [2] af 99 }

  condition:
    any of them
}