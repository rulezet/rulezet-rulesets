rule TTP_XOR_QUAD_CurrentVersionRun_7fe8 {
  strings:
    $key_7fe8 = { 2c 87 [2] 08 89 [2] 23 a5 [2] 0d 87 [2] 19 9c [2] 16 86 [2] 08 9b [2] 0a 9a [2] 11 9c [2] 0d 9b [2] 11 b4 }

  condition:
    any of them
}