rule TTP_XOR_QUAD_CurrentVersionRun_c634 {
  strings:
    $key_c634 = { 95 5b [2] b1 55 [2] 9a 79 [2] b4 5b [2] a0 40 [2] af 5a [2] b1 47 [2] b3 46 [2] a8 40 [2] b4 47 [2] a8 68 }

  condition:
    any of them
}