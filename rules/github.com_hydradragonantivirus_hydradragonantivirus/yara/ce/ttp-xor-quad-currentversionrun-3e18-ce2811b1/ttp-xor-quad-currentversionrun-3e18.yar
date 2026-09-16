rule TTP_XOR_QUAD_CurrentVersionRun_3e18 {
  strings:
    $key_3e18 = { 6d 77 [2] 49 79 [2] 62 55 [2] 4c 77 [2] 58 6c [2] 57 76 [2] 49 6b [2] 4b 6a [2] 50 6c [2] 4c 6b [2] 50 44 }

  condition:
    any of them
}