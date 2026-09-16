rule TTP_XOR_QUAD_CurrentVersionRun_c134 {
  strings:
    $key_c134 = { 92 5b [2] b6 55 [2] 9d 79 [2] b3 5b [2] a7 40 [2] a8 5a [2] b6 47 [2] b4 46 [2] af 40 [2] b3 47 [2] af 68 }

  condition:
    any of them
}