rule TTP_XOR_QUAD_CurrentVersionRun_c734 {
  strings:
    $key_c734 = { 94 5b [2] b0 55 [2] 9b 79 [2] b5 5b [2] a1 40 [2] ae 5a [2] b0 47 [2] b2 46 [2] a9 40 [2] b5 47 [2] a9 68 }

  condition:
    any of them
}