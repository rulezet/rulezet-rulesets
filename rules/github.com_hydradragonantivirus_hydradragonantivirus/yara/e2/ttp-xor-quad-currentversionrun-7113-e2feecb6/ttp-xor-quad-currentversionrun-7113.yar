rule TTP_XOR_QUAD_CurrentVersionRun_7113 {
  strings:
    $key_7113 = { 22 7c [2] 06 72 [2] 2d 5e [2] 03 7c [2] 17 67 [2] 18 7d [2] 06 60 [2] 04 61 [2] 1f 67 [2] 03 60 [2] 1f 4f }

  condition:
    any of them
}