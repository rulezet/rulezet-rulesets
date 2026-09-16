rule TTP_XOR_QUAD_CurrentVersionRun_c1e4 {
  strings:
    $key_c1e4 = { 92 8b [2] b6 85 [2] 9d a9 [2] b3 8b [2] a7 90 [2] a8 8a [2] b6 97 [2] b4 96 [2] af 90 [2] b3 97 [2] af b8 }

  condition:
    any of them
}