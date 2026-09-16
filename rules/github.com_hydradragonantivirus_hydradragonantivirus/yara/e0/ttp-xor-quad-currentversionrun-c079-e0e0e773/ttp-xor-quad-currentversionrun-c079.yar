rule TTP_XOR_QUAD_CurrentVersionRun_c079 {
  strings:
    $key_c079 = { 93 16 [2] b7 18 [2] 9c 34 [2] b2 16 [2] a6 0d [2] a9 17 [2] b7 0a [2] b5 0b [2] ae 0d [2] b2 0a [2] ae 25 }

  condition:
    any of them
}