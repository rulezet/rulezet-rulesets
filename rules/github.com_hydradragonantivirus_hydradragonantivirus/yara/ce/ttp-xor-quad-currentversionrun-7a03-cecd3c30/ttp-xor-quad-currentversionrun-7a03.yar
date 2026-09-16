rule TTP_XOR_QUAD_CurrentVersionRun_7a03 {
  strings:
    $key_7a03 = { 29 6c [2] 0d 62 [2] 26 4e [2] 08 6c [2] 1c 77 [2] 13 6d [2] 0d 70 [2] 0f 71 [2] 14 77 [2] 08 70 [2] 14 5f }

  condition:
    any of them
}