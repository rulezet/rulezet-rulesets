rule TTP_XOR_QUAD_CurrentVersionRun_fc03 {
  strings:
    $key_fc03 = { af 6c [2] 8b 62 [2] a0 4e [2] 8e 6c [2] 9a 77 [2] 95 6d [2] 8b 70 [2] 89 71 [2] 92 77 [2] 8e 70 [2] 92 5f }

  condition:
    any of them
}