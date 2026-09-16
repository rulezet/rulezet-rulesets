rule TTP_XOR_QUAD_CurrentVersionRun_3a23 {
  strings:
    $key_3a23 = { 69 4c [2] 4d 42 [2] 66 6e [2] 48 4c [2] 5c 57 [2] 53 4d [2] 4d 50 [2] 4f 51 [2] 54 57 [2] 48 50 [2] 54 7f }

  condition:
    any of them
}