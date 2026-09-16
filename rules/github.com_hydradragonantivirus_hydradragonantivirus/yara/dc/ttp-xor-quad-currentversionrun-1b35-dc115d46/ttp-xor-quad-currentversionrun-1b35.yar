rule TTP_XOR_QUAD_CurrentVersionRun_1b35 {
  strings:
    $key_1b35 = { 48 5a [2] 6c 54 [2] 47 78 [2] 69 5a [2] 7d 41 [2] 72 5b [2] 6c 46 [2] 6e 47 [2] 75 41 [2] 69 46 [2] 75 69 }

  condition:
    any of them
}