rule TTP_XOR_QUAD_CurrentVersionRun_2123 {
  strings:
    $key_2123 = { 72 4c [2] 56 42 [2] 7d 6e [2] 53 4c [2] 47 57 [2] 48 4d [2] 56 50 [2] 54 51 [2] 4f 57 [2] 53 50 [2] 4f 7f }

  condition:
    any of them
}