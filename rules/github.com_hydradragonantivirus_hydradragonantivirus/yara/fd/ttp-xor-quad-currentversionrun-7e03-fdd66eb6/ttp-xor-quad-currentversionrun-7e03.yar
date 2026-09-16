rule TTP_XOR_QUAD_CurrentVersionRun_7e03 {
  strings:
    $key_7e03 = { 2d 6c [2] 09 62 [2] 22 4e [2] 0c 6c [2] 18 77 [2] 17 6d [2] 09 70 [2] 0b 71 [2] 10 77 [2] 0c 70 [2] 10 5f }

  condition:
    any of them
}