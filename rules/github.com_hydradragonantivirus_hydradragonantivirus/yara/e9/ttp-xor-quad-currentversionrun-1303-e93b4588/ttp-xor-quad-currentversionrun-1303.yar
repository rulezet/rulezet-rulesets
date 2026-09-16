rule TTP_XOR_QUAD_CurrentVersionRun_1303 {
  strings:
    $key_1303 = { 40 6c [2] 64 62 [2] 4f 4e [2] 61 6c [2] 75 77 [2] 7a 6d [2] 64 70 [2] 66 71 [2] 7d 77 [2] 61 70 [2] 7d 5f }

  condition:
    any of them
}