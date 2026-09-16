rule TTP_XOR_QUAD_CurrentVersionRun_2004 {
  strings:
    $key_2004 = { 73 6b [2] 57 65 [2] 7c 49 [2] 52 6b [2] 46 70 [2] 49 6a [2] 57 77 [2] 55 76 [2] 4e 70 [2] 52 77 [2] 4e 58 }

  condition:
    any of them
}