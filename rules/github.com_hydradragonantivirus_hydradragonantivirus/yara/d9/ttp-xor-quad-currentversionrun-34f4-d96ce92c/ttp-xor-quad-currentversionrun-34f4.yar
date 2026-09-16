rule TTP_XOR_QUAD_CurrentVersionRun_34f4 {
  strings:
    $key_34f4 = { 67 9b [2] 43 95 [2] 68 b9 [2] 46 9b [2] 52 80 [2] 5d 9a [2] 43 87 [2] 41 86 [2] 5a 80 [2] 46 87 [2] 5a a8 }

  condition:
    any of them
}