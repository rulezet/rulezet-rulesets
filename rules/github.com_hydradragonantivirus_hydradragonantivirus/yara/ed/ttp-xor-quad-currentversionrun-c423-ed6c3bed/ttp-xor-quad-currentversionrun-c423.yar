rule TTP_XOR_QUAD_CurrentVersionRun_c423 {
  strings:
    $key_c423 = { 97 4c [2] b3 42 [2] 98 6e [2] b6 4c [2] a2 57 [2] ad 4d [2] b3 50 [2] b1 51 [2] aa 57 [2] b6 50 [2] aa 7f }

  condition:
    any of them
}