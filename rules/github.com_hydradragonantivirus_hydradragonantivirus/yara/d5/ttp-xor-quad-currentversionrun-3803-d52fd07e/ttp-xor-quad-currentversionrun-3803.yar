rule TTP_XOR_QUAD_CurrentVersionRun_3803 {
  strings:
    $key_3803 = { 6b 6c [2] 4f 62 [2] 64 4e [2] 4a 6c [2] 5e 77 [2] 51 6d [2] 4f 70 [2] 4d 71 [2] 56 77 [2] 4a 70 [2] 56 5f }

  condition:
    any of them
}