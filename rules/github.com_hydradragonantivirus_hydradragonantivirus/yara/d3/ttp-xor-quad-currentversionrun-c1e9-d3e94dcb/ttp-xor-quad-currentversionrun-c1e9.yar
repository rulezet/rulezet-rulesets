rule TTP_XOR_QUAD_CurrentVersionRun_c1e9 {
  strings:
    $key_c1e9 = { 92 86 [2] b6 88 [2] 9d a4 [2] b3 86 [2] a7 9d [2] a8 87 [2] b6 9a [2] b4 9b [2] af 9d [2] b3 9a [2] af b5 }

  condition:
    any of them
}