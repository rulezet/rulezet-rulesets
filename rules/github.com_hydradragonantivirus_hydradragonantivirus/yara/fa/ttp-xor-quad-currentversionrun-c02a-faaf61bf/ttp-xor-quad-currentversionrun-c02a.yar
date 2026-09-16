rule TTP_XOR_QUAD_CurrentVersionRun_c02a {
  strings:
    $key_c02a = { 93 45 [2] b7 4b [2] 9c 67 [2] b2 45 [2] a6 5e [2] a9 44 [2] b7 59 [2] b5 58 [2] ae 5e [2] b2 59 [2] ae 76 }

  condition:
    any of them
}