rule TTP_XOR_QUAD_CurrentVersionRun_7120 {
  strings:
    $key_7120 = { 22 4f [2] 06 41 [2] 2d 6d [2] 03 4f [2] 17 54 [2] 18 4e [2] 06 53 [2] 04 52 [2] 1f 54 [2] 03 53 [2] 1f 7c }

  condition:
    any of them
}