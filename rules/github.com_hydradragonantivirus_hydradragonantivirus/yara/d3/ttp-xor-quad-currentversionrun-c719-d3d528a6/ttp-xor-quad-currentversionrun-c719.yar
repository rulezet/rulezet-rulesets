rule TTP_XOR_QUAD_CurrentVersionRun_c719 {
  strings:
    $key_c719 = { 94 76 [2] b0 78 [2] 9b 54 [2] b5 76 [2] a1 6d [2] ae 77 [2] b0 6a [2] b2 6b [2] a9 6d [2] b5 6a [2] a9 45 }

  condition:
    any of them
}