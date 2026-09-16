rule TTP_XOR_QUAD_CurrentVersionRun_6c19 {
  strings:
    $key_6c19 = { 3f 76 [2] 1b 78 [2] 30 54 [2] 1e 76 [2] 0a 6d [2] 05 77 [2] 1b 6a [2] 19 6b [2] 02 6d [2] 1e 6a [2] 02 45 }

  condition:
    any of them
}