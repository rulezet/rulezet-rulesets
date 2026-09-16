rule TTP_XOR_QUAD_CurrentVersionRun_2039 {
  strings:
    $key_2039 = { 73 56 [2] 57 58 [2] 7c 74 [2] 52 56 [2] 46 4d [2] 49 57 [2] 57 4a [2] 55 4b [2] 4e 4d [2] 52 4a [2] 4e 65 }

  condition:
    any of them
}