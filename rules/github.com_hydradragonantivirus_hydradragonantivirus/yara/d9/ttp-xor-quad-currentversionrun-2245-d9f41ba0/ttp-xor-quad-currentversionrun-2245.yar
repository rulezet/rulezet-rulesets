rule TTP_XOR_QUAD_CurrentVersionRun_2245 {
  strings:
    $key_2245 = { 71 2a [2] 55 24 [2] 7e 08 [2] 50 2a [2] 44 31 [2] 4b 2b [2] 55 36 [2] 57 37 [2] 4c 31 [2] 50 36 [2] 4c 19 }

  condition:
    any of them
}