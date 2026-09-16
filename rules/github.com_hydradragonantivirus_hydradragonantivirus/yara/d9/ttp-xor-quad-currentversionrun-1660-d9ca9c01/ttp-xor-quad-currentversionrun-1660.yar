rule TTP_XOR_QUAD_CurrentVersionRun_1660 {
  strings:
    $key_1660 = { 45 0f [2] 61 01 [2] 4a 2d [2] 64 0f [2] 70 14 [2] 7f 0e [2] 61 13 [2] 63 12 [2] 78 14 [2] 64 13 [2] 78 3c }

  condition:
    any of them
}