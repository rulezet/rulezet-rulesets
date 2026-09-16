rule TTP_XOR_QUAD_CurrentVersionRun_2007 {
  strings:
    $key_2007 = { 73 68 [2] 57 66 [2] 7c 4a [2] 52 68 [2] 46 73 [2] 49 69 [2] 57 74 [2] 55 75 [2] 4e 73 [2] 52 74 [2] 4e 5b }

  condition:
    any of them
}