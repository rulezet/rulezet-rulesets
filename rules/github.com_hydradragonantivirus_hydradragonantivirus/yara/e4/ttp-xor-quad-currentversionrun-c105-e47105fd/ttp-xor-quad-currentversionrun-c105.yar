rule TTP_XOR_QUAD_CurrentVersionRun_c105 {
  strings:
    $key_c105 = { 92 6a [2] b6 64 [2] 9d 48 [2] b3 6a [2] a7 71 [2] a8 6b [2] b6 76 [2] b4 77 [2] af 71 [2] b3 76 [2] af 59 }

  condition:
    any of them
}