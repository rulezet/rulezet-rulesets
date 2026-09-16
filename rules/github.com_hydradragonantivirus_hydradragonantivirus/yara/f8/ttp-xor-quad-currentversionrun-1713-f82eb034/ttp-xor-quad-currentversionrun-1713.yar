rule TTP_XOR_QUAD_CurrentVersionRun_1713 {
  strings:
    $key_1713 = { 44 7c [2] 60 72 [2] 4b 5e [2] 65 7c [2] 71 67 [2] 7e 7d [2] 60 60 [2] 62 61 [2] 79 67 [2] 65 60 [2] 79 4f }

  condition:
    any of them
}