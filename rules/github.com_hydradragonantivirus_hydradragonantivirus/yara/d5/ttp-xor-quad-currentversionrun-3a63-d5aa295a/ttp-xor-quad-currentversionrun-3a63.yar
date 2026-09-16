rule TTP_XOR_QUAD_CurrentVersionRun_3a63 {
  strings:
    $key_3a63 = { 69 0c [2] 4d 02 [2] 66 2e [2] 48 0c [2] 5c 17 [2] 53 0d [2] 4d 10 [2] 4f 11 [2] 54 17 [2] 48 10 [2] 54 3f }

  condition:
    any of them
}