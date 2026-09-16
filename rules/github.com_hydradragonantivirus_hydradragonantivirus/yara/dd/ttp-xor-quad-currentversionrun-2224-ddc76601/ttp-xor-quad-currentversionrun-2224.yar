rule TTP_XOR_QUAD_CurrentVersionRun_2224 {
  strings:
    $key_2224 = { 71 4b [2] 55 45 [2] 7e 69 [2] 50 4b [2] 44 50 [2] 4b 4a [2] 55 57 [2] 57 56 [2] 4c 50 [2] 50 57 [2] 4c 78 }

  condition:
    any of them
}