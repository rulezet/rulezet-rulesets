rule TTP_XOR_QUAD_CurrentVersionRun_7110 {
  strings:
    $key_7110 = { 22 7f [2] 06 71 [2] 2d 5d [2] 03 7f [2] 17 64 [2] 18 7e [2] 06 63 [2] 04 62 [2] 1f 64 [2] 03 63 [2] 1f 4c }

  condition:
    any of them
}