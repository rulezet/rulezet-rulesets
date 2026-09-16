rule TTP_XOR_QUAD_CurrentVersionRun_1b09 {
  strings:
    $key_1b09 = { 48 66 [2] 6c 68 [2] 47 44 [2] 69 66 [2] 7d 7d [2] 72 67 [2] 6c 7a [2] 6e 7b [2] 75 7d [2] 69 7a [2] 75 55 }

  condition:
    any of them
}