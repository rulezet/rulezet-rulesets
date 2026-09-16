rule TTP_XOR_QUAD_CurrentVersionRun_1518 {
  strings:
    $key_1518 = { 46 77 [2] 62 79 [2] 49 55 [2] 67 77 [2] 73 6c [2] 7c 76 [2] 62 6b [2] 60 6a [2] 7b 6c [2] 67 6b [2] 7b 44 }

  condition:
    any of them
}