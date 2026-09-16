rule TTP_XOR_QUAD_CurrentVersionRun_2303 {
  strings:
    $key_2303 = { 70 6c [2] 54 62 [2] 7f 4e [2] 51 6c [2] 45 77 [2] 4a 6d [2] 54 70 [2] 56 71 [2] 4d 77 [2] 51 70 [2] 4d 5f }

  condition:
    any of them
}