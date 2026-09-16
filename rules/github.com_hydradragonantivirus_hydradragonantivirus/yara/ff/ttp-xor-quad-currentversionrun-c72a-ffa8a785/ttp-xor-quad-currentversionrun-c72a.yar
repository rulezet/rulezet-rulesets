rule TTP_XOR_QUAD_CurrentVersionRun_c72a {
  strings:
    $key_c72a = { 94 45 [2] b0 4b [2] 9b 67 [2] b5 45 [2] a1 5e [2] ae 44 [2] b0 59 [2] b2 58 [2] a9 5e [2] b5 59 [2] a9 76 }

  condition:
    any of them
}