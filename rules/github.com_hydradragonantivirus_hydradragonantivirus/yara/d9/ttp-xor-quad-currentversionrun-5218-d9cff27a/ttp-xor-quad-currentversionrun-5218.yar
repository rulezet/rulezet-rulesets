rule TTP_XOR_QUAD_CurrentVersionRun_5218 {
  strings:
    $key_5218 = { 01 77 [2] 25 79 [2] 0e 55 [2] 20 77 [2] 34 6c [2] 3b 76 [2] 25 6b [2] 27 6a [2] 3c 6c [2] 20 6b [2] 3c 44 }

  condition:
    any of them
}