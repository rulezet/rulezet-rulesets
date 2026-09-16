rule TTP_XOR_QUAD_CurrentVersionRun_3713 {
  strings:
    $key_3713 = { 64 7c [2] 40 72 [2] 6b 5e [2] 45 7c [2] 51 67 [2] 5e 7d [2] 40 60 [2] 42 61 [2] 59 67 [2] 45 60 [2] 59 4f }

  condition:
    any of them
}