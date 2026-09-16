rule TTP_XOR_QUAD_CurrentVersionRun_c114 {
  strings:
    $key_c114 = { 92 7b [2] b6 75 [2] 9d 59 [2] b3 7b [2] a7 60 [2] a8 7a [2] b6 67 [2] b4 66 [2] af 60 [2] b3 67 [2] af 48 }

  condition:
    any of them
}