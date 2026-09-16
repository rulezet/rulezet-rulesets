rule TTP_XOR_QUAD_CurrentVersionRun_c076 {
  strings:
    $key_c076 = { 93 19 [2] b7 17 [2] 9c 3b [2] b2 19 [2] a6 02 [2] a9 18 [2] b7 05 [2] b5 04 [2] ae 02 [2] b2 05 [2] ae 2a }

  condition:
    any of them
}