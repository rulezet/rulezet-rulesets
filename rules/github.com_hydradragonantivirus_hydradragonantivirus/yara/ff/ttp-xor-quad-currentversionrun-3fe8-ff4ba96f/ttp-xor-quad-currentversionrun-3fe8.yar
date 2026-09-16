rule TTP_XOR_QUAD_CurrentVersionRun_3fe8 {
  strings:
    $key_3fe8 = { 6c 87 [2] 48 89 [2] 63 a5 [2] 4d 87 [2] 59 9c [2] 56 86 [2] 48 9b [2] 4a 9a [2] 51 9c [2] 4d 9b [2] 51 b4 }

  condition:
    any of them
}