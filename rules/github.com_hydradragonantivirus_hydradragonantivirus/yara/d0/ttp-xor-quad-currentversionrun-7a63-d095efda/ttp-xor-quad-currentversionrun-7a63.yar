rule TTP_XOR_QUAD_CurrentVersionRun_7a63 {
  strings:
    $key_7a63 = { 29 0c [2] 0d 02 [2] 26 2e [2] 08 0c [2] 1c 17 [2] 13 0d [2] 0d 10 [2] 0f 11 [2] 14 17 [2] 08 10 [2] 14 3f }

  condition:
    any of them
}