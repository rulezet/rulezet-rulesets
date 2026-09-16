rule TTP_XOR_QUAD_CurrentVersionRun_1c13 {
  strings:
    $key_1c13 = { 4f 7c [2] 6b 72 [2] 40 5e [2] 6e 7c [2] 7a 67 [2] 75 7d [2] 6b 60 [2] 69 61 [2] 72 67 [2] 6e 60 [2] 72 4f }

  condition:
    any of them
}