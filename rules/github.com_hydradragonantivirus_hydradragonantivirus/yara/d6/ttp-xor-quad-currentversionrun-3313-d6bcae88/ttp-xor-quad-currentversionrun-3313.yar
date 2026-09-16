rule TTP_XOR_QUAD_CurrentVersionRun_3313 {
  strings:
    $key_3313 = { 60 7c [2] 44 72 [2] 6f 5e [2] 41 7c [2] 55 67 [2] 5a 7d [2] 44 60 [2] 46 61 [2] 5d 67 [2] 41 60 [2] 5d 4f }

  condition:
    any of them
}