rule TTP_XOR_QUAD_CurrentVersionRun_3423 {
  strings:
    $key_3423 = { 67 4c [2] 43 42 [2] 68 6e [2] 46 4c [2] 52 57 [2] 5d 4d [2] 43 50 [2] 41 51 [2] 5a 57 [2] 46 50 [2] 5a 7f }

  condition:
    any of them
}