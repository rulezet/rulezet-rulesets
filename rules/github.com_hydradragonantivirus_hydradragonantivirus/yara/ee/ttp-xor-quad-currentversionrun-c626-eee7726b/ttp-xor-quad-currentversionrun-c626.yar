rule TTP_XOR_QUAD_CurrentVersionRun_c626 {
  strings:
    $key_c626 = { 95 49 [2] b1 47 [2] 9a 6b [2] b4 49 [2] a0 52 [2] af 48 [2] b1 55 [2] b3 54 [2] a8 52 [2] b4 55 [2] a8 7a }

  condition:
    any of them
}