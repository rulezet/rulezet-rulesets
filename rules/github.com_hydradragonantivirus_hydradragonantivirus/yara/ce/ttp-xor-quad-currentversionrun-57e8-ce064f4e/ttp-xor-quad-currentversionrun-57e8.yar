rule TTP_XOR_QUAD_CurrentVersionRun_57e8 {
  strings:
    $key_57e8 = { 04 87 [2] 20 89 [2] 0b a5 [2] 25 87 [2] 31 9c [2] 3e 86 [2] 20 9b [2] 22 9a [2] 39 9c [2] 25 9b [2] 39 b4 }

  condition:
    any of them
}