rule TTP_XOR_QUAD_CurrentVersionRun_c74a {
  strings:
    $key_c74a = { 94 25 [2] b0 2b [2] 9b 07 [2] b5 25 [2] a1 3e [2] ae 24 [2] b0 39 [2] b2 38 [2] a9 3e [2] b5 39 [2] a9 16 }

  condition:
    any of them
}