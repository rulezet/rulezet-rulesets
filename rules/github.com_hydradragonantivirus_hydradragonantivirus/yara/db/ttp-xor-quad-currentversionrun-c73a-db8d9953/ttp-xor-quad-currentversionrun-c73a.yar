rule TTP_XOR_QUAD_CurrentVersionRun_c73a {
  strings:
    $key_c73a = { 94 55 [2] b0 5b [2] 9b 77 [2] b5 55 [2] a1 4e [2] ae 54 [2] b0 49 [2] b2 48 [2] a9 4e [2] b5 49 [2] a9 66 }

  condition:
    any of them
}