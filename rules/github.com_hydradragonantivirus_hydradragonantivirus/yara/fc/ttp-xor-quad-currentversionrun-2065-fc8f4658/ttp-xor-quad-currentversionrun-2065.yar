rule TTP_XOR_QUAD_CurrentVersionRun_2065 {
  strings:
    $key_2065 = { 73 0a [2] 57 04 [2] 7c 28 [2] 52 0a [2] 46 11 [2] 49 0b [2] 57 16 [2] 55 17 [2] 4e 11 [2] 52 16 [2] 4e 39 }

  condition:
    any of them
}