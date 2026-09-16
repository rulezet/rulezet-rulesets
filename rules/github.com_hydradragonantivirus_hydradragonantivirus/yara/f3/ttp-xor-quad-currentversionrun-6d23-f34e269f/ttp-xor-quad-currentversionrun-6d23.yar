rule TTP_XOR_QUAD_CurrentVersionRun_6d23 {
  strings:
    $key_6d23 = { 3e 4c [2] 1a 42 [2] 31 6e [2] 1f 4c [2] 0b 57 [2] 04 4d [2] 1a 50 [2] 18 51 [2] 03 57 [2] 1f 50 [2] 03 7f }

  condition:
    any of them
}