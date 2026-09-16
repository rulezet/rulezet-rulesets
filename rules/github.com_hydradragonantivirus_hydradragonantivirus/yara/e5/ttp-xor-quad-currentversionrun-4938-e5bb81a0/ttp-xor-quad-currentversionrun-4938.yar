rule TTP_XOR_QUAD_CurrentVersionRun_4938 {
  strings:
    $key_4938 = { 1a 57 [2] 3e 59 [2] 15 75 [2] 3b 57 [2] 2f 4c [2] 20 56 [2] 3e 4b [2] 3c 4a [2] 27 4c [2] 3b 4b [2] 27 64 }

  condition:
    any of them
}