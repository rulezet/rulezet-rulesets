rule TTP_XOR_QUAD_CurrentVersionRun_c064 {
  strings:
    $key_c064 = { 93 0b [2] b7 05 [2] 9c 29 [2] b2 0b [2] a6 10 [2] a9 0a [2] b7 17 [2] b5 16 [2] ae 10 [2] b2 17 [2] ae 38 }

  condition:
    any of them
}