rule TTP_XOR_QUAD_CurrentVersionRun_3b23 {
  strings:
    $key_3b23 = { 68 4c [2] 4c 42 [2] 67 6e [2] 49 4c [2] 5d 57 [2] 52 4d [2] 4c 50 [2] 4e 51 [2] 55 57 [2] 49 50 [2] 55 7f }

  condition:
    any of them
}