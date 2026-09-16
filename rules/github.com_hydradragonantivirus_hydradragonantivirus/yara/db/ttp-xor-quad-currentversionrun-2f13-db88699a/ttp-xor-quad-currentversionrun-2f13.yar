rule TTP_XOR_QUAD_CurrentVersionRun_2f13 {
  strings:
    $key_2f13 = { 7c 7c [2] 58 72 [2] 73 5e [2] 5d 7c [2] 49 67 [2] 46 7d [2] 58 60 [2] 5a 61 [2] 41 67 [2] 5d 60 [2] 41 4f }

  condition:
    any of them
}