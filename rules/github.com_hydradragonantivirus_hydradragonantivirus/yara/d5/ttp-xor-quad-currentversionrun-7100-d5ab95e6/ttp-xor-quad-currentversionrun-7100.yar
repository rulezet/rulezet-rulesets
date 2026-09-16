rule TTP_XOR_QUAD_CurrentVersionRun_7100 {
  strings:
    $key_7100 = { 22 6f [2] 06 61 [2] 2d 4d [2] 03 6f [2] 17 74 [2] 18 6e [2] 06 73 [2] 04 72 [2] 1f 74 [2] 03 73 [2] 1f 5c }

  condition:
    any of them
}