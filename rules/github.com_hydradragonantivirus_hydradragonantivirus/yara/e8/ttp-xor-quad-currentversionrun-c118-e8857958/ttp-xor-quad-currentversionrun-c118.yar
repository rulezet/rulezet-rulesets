rule TTP_XOR_QUAD_CurrentVersionRun_c118 {
  strings:
    $key_c118 = { 92 77 [2] b6 79 [2] 9d 55 [2] b3 77 [2] a7 6c [2] a8 76 [2] b6 6b [2] b4 6a [2] af 6c [2] b3 6b [2] af 44 }

  condition:
    any of them
}