rule TTP_XOR_QUAD_CurrentVersionRun_3b03 {
  strings:
    $key_3b03 = { 68 6c [2] 4c 62 [2] 67 4e [2] 49 6c [2] 5d 77 [2] 52 6d [2] 4c 70 [2] 4e 71 [2] 55 77 [2] 49 70 [2] 55 5f }

  condition:
    any of them
}