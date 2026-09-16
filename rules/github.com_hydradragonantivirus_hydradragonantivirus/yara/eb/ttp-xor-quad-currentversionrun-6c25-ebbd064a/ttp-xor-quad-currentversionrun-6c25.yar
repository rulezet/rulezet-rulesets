rule TTP_XOR_QUAD_CurrentVersionRun_6c25 {
  strings:
    $key_6c25 = { 3f 4a [2] 1b 44 [2] 30 68 [2] 1e 4a [2] 0a 51 [2] 05 4b [2] 1b 56 [2] 19 57 [2] 02 51 [2] 1e 56 [2] 02 79 }

  condition:
    any of them
}