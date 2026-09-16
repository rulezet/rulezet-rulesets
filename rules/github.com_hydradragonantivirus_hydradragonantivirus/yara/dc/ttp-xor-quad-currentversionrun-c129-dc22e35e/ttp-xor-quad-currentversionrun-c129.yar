rule TTP_XOR_QUAD_CurrentVersionRun_c129 {
  strings:
    $key_c129 = { 92 46 [2] b6 48 [2] 9d 64 [2] b3 46 [2] a7 5d [2] a8 47 [2] b6 5a [2] b4 5b [2] af 5d [2] b3 5a [2] af 75 }

  condition:
    any of them
}