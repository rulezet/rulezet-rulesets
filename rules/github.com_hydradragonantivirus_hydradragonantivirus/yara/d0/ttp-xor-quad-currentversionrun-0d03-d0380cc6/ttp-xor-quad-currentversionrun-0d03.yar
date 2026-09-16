rule TTP_XOR_QUAD_CurrentVersionRun_0d03 {
  strings:
    $key_0d03 = { 5e 6c [2] 7a 62 [2] 51 4e [2] 7f 6c [2] 6b 77 [2] 64 6d [2] 7a 70 [2] 78 71 [2] 63 77 [2] 7f 70 [2] 63 5f }

  condition:
    any of them
}