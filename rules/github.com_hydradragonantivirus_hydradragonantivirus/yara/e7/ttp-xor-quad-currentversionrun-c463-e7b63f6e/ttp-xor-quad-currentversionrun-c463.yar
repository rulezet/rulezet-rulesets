rule TTP_XOR_QUAD_CurrentVersionRun_c463 {
  strings:
    $key_c463 = { 97 0c [2] b3 02 [2] 98 2e [2] b6 0c [2] a2 17 [2] ad 0d [2] b3 10 [2] b1 11 [2] aa 17 [2] b6 10 [2] aa 3f }

  condition:
    any of them
}