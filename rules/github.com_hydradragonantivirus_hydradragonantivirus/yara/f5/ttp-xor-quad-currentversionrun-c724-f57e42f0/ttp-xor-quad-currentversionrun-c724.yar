rule TTP_XOR_QUAD_CurrentVersionRun_c724 {
  strings:
    $key_c724 = { 94 4b [2] b0 45 [2] 9b 69 [2] b5 4b [2] a1 50 [2] ae 4a [2] b0 57 [2] b2 56 [2] a9 50 [2] b5 57 [2] a9 78 }

  condition:
    any of them
}