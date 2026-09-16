rule TTP_XOR_QUAD_CurrentVersionRun_2413 {
  strings:
    $key_2413 = { 77 7c [2] 53 72 [2] 78 5e [2] 56 7c [2] 42 67 [2] 4d 7d [2] 53 60 [2] 51 61 [2] 4a 67 [2] 56 60 [2] 4a 4f }

  condition:
    any of them
}