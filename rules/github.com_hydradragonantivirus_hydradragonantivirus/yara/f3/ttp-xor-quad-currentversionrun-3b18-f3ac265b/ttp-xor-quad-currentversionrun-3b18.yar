rule TTP_XOR_QUAD_CurrentVersionRun_3b18 {
  strings:
    $key_3b18 = { 68 77 [2] 4c 79 [2] 67 55 [2] 49 77 [2] 5d 6c [2] 52 76 [2] 4c 6b [2] 4e 6a [2] 55 6c [2] 49 6b [2] 55 44 }

  condition:
    any of them
}