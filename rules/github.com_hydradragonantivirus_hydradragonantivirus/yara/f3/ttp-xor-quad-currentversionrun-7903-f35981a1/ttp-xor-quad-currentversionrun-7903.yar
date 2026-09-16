rule TTP_XOR_QUAD_CurrentVersionRun_7903 {
  strings:
    $key_7903 = { 2a 6c [2] 0e 62 [2] 25 4e [2] 0b 6c [2] 1f 77 [2] 10 6d [2] 0e 70 [2] 0c 71 [2] 17 77 [2] 0b 70 [2] 17 5f }

  condition:
    any of them
}