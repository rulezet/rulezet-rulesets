rule TTP_XOR_QUAD_CurrentVersionRun_4b23 {
  strings:
    $key_4b23 = { 18 4c [2] 3c 42 [2] 17 6e [2] 39 4c [2] 2d 57 [2] 22 4d [2] 3c 50 [2] 3e 51 [2] 25 57 [2] 39 50 [2] 25 7f }

  condition:
    any of them
}