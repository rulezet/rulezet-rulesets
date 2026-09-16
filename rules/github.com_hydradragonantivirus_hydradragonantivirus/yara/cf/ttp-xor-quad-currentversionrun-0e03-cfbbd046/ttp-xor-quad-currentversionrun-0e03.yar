rule TTP_XOR_QUAD_CurrentVersionRun_0e03 {
  strings:
    $key_0e03 = { 5d 6c [2] 79 62 [2] 52 4e [2] 7c 6c [2] 68 77 [2] 67 6d [2] 79 70 [2] 7b 71 [2] 60 77 [2] 7c 70 [2] 60 5f }

  condition:
    any of them
}