rule TTP_XOR_QUAD_CurrentVersionRun_6248 {
  strings:
    $key_6248 = { 31 27 [2] 15 29 [2] 3e 05 [2] 10 27 [2] 04 3c [2] 0b 26 [2] 15 3b [2] 17 3a [2] 0c 3c [2] 10 3b [2] 0c 14 }

  condition:
    any of them
}