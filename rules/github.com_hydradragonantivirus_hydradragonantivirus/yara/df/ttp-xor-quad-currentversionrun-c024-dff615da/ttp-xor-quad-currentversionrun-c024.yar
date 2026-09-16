rule TTP_XOR_QUAD_CurrentVersionRun_c024 {
  strings:
    $key_c024 = { 93 4b [2] b7 45 [2] 9c 69 [2] b2 4b [2] a6 50 [2] a9 4a [2] b7 57 [2] b5 56 [2] ae 50 [2] b2 57 [2] ae 78 }

  condition:
    any of them
}