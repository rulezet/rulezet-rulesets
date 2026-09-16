rule TTP_XOR_QUAD_CurrentVersionRun_c614 {
  strings:
    $key_c614 = { 95 7b [2] b1 75 [2] 9a 59 [2] b4 7b [2] a0 60 [2] af 7a [2] b1 67 [2] b3 66 [2] a8 60 [2] b4 67 [2] a8 48 }

  condition:
    any of them
}