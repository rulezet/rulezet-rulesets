rule TTP_XOR_QUAD_CurrentVersionRun_c128 {
  strings:
    $key_c128 = { 92 47 [2] b6 49 [2] 9d 65 [2] b3 47 [2] a7 5c [2] a8 46 [2] b6 5b [2] b4 5a [2] af 5c [2] b3 5b [2] af 74 }

  condition:
    any of them
}