rule TTP_XOR_QUAD_CurrentVersionRun_c776 {
  strings:
    $key_c776 = { 94 19 [2] b0 17 [2] 9b 3b [2] b5 19 [2] a1 02 [2] ae 18 [2] b0 05 [2] b2 04 [2] a9 02 [2] b5 05 [2] a9 2a }

  condition:
    any of them
}