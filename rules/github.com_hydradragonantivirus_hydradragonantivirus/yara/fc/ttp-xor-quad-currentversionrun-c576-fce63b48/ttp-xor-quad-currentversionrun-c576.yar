rule TTP_XOR_QUAD_CurrentVersionRun_c576 {
  strings:
    $key_c576 = { 96 19 [2] b2 17 [2] 99 3b [2] b7 19 [2] a3 02 [2] ac 18 [2] b2 05 [2] b0 04 [2] ab 02 [2] b7 05 [2] ab 2a }

  condition:
    any of them
}