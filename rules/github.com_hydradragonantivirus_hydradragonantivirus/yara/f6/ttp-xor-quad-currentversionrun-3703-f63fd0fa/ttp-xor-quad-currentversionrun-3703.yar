rule TTP_XOR_QUAD_CurrentVersionRun_3703 {
  strings:
    $key_3703 = { 64 6c [2] 40 62 [2] 6b 4e [2] 45 6c [2] 51 77 [2] 5e 6d [2] 40 70 [2] 42 71 [2] 59 77 [2] 45 70 [2] 59 5f }

  condition:
    any of them
}