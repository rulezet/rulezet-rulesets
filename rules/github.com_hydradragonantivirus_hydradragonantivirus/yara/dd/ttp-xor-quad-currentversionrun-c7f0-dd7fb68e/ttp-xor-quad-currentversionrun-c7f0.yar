rule TTP_XOR_QUAD_CurrentVersionRun_c7f0 {
  strings:
    $key_c7f0 = { 94 9f [2] b0 91 [2] 9b bd [2] b5 9f [2] a1 84 [2] ae 9e [2] b0 83 [2] b2 82 [2] a9 84 [2] b5 83 [2] a9 ac }

  condition:
    any of them
}