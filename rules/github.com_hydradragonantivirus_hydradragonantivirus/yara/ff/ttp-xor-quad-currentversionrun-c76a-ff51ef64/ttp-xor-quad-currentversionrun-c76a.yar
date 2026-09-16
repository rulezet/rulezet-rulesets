rule TTP_XOR_QUAD_CurrentVersionRun_c76a {
  strings:
    $key_c76a = { 94 05 [2] b0 0b [2] 9b 27 [2] b5 05 [2] a1 1e [2] ae 04 [2] b0 19 [2] b2 18 [2] a9 1e [2] b5 19 [2] a9 36 }

  condition:
    any of them
}