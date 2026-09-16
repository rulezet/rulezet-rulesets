rule TTP_XOR_QUAD_CurrentVersionRun_0003 {
  strings:
    $key_0003 = { 53 6c [2] 77 62 [2] 5c 4e [2] 72 6c [2] 66 77 [2] 69 6d [2] 77 70 [2] 75 71 [2] 6e 77 [2] 72 70 [2] 6e 5f }

  condition:
    any of them
}