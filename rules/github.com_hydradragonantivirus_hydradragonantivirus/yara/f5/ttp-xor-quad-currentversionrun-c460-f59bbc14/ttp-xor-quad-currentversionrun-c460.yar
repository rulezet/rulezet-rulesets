rule TTP_XOR_QUAD_CurrentVersionRun_c460 {
  strings:
    $key_c460 = { 97 0f [2] b3 01 [2] 98 2d [2] b6 0f [2] a2 14 [2] ad 0e [2] b3 13 [2] b1 12 [2] aa 14 [2] b6 13 [2] aa 3c }

  condition:
    any of them
}