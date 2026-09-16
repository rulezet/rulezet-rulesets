rule TTP_XOR_QUAD_CurrentVersionRun_c71f {
  strings:
    $key_c71f = { 94 70 [2] b0 7e [2] 9b 52 [2] b5 70 [2] a1 6b [2] ae 71 [2] b0 6c [2] b2 6d [2] a9 6b [2] b5 6c [2] a9 43 }

  condition:
    any of them
}