rule TTP_XOR_QUAD_CurrentVersionRun_c403 {
  strings:
    $key_c403 = { 97 6c [2] b3 62 [2] 98 4e [2] b6 6c [2] a2 77 [2] ad 6d [2] b3 70 [2] b1 71 [2] aa 77 [2] b6 70 [2] aa 5f }

  condition:
    any of them
}