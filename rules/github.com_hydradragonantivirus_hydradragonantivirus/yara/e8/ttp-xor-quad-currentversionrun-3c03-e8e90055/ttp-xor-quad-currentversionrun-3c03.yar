rule TTP_XOR_QUAD_CurrentVersionRun_3c03 {
  strings:
    $key_3c03 = { 6f 6c [2] 4b 62 [2] 60 4e [2] 4e 6c [2] 5a 77 [2] 55 6d [2] 4b 70 [2] 49 71 [2] 52 77 [2] 4e 70 [2] 52 5f }

  condition:
    any of them
}