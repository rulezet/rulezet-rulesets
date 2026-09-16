rule TTP_XOR_QUAD_CurrentVersionRun_c72e {
  strings:
    $key_c72e = { 94 41 [2] b0 4f [2] 9b 63 [2] b5 41 [2] a1 5a [2] ae 40 [2] b0 5d [2] b2 5c [2] a9 5a [2] b5 5d [2] a9 72 }

  condition:
    any of them
}