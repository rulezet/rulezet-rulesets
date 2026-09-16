rule TTP_XOR_QUAD_CurrentVersionRun_7313 {
  strings:
    $key_7313 = { 20 7c [2] 04 72 [2] 2f 5e [2] 01 7c [2] 15 67 [2] 1a 7d [2] 04 60 [2] 06 61 [2] 1d 67 [2] 01 60 [2] 1d 4f }

  condition:
    any of them
}