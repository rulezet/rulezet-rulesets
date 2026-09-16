rule TTP_XOR_QUAD_CurrentVersionRun_c303 {
  strings:
    $key_c303 = { 90 6c [2] b4 62 [2] 9f 4e [2] b1 6c [2] a5 77 [2] aa 6d [2] b4 70 [2] b6 71 [2] ad 77 [2] b1 70 [2] ad 5f }

  condition:
    any of them
}