rule TTP_XOR_QUAD_CurrentVersionRun_20f4 {
  strings:
    $key_20f4 = { 73 9b [2] 57 95 [2] 7c b9 [2] 52 9b [2] 46 80 [2] 49 9a [2] 57 87 [2] 55 86 [2] 4e 80 [2] 52 87 [2] 4e a8 }

  condition:
    any of them
}