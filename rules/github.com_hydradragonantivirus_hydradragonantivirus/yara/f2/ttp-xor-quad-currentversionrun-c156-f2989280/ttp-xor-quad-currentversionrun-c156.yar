rule TTP_XOR_QUAD_CurrentVersionRun_c156 {
  strings:
    $key_c156 = { 92 39 [2] b6 37 [2] 9d 1b [2] b3 39 [2] a7 22 [2] a8 38 [2] b6 25 [2] b4 24 [2] af 22 [2] b3 25 [2] af 0a }

  condition:
    any of them
}