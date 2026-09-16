rule TTP_XOR_QUAD_CurrentVersionRun_c01b {
  strings:
    $key_c01b = { 93 74 [2] b7 7a [2] 9c 56 [2] b2 74 [2] a6 6f [2] a9 75 [2] b7 68 [2] b5 69 [2] ae 6f [2] b2 68 [2] ae 47 }

  condition:
    any of them
}