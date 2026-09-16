rule TTP_XOR_QUAD_CurrentVersionRun_0d60 {
  strings:
    $key_0d60 = { 5e 0f [2] 7a 01 [2] 51 2d [2] 7f 0f [2] 6b 14 [2] 64 0e [2] 7a 13 [2] 78 12 [2] 63 14 [2] 7f 13 [2] 63 3c }

  condition:
    any of them
}