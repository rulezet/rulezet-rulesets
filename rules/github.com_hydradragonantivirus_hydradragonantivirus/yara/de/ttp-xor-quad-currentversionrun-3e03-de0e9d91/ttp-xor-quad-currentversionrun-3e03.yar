rule TTP_XOR_QUAD_CurrentVersionRun_3e03 {
  strings:
    $key_3e03 = { 6d 6c [2] 49 62 [2] 62 4e [2] 4c 6c [2] 58 77 [2] 57 6d [2] 49 70 [2] 4b 71 [2] 50 77 [2] 4c 70 [2] 50 5f }

  condition:
    any of them
}