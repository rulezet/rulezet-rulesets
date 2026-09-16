rule TTP_XOR_QUAD_CurrentVersionRun_c410 {
  strings:
    $key_c410 = { 97 7f [2] b3 71 [2] 98 5d [2] b6 7f [2] a2 64 [2] ad 7e [2] b3 63 [2] b1 62 [2] aa 64 [2] b6 63 [2] aa 4c }

  condition:
    any of them
}