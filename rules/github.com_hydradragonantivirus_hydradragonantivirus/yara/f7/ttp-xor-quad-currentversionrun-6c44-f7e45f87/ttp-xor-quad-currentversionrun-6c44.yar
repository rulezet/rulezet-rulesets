rule TTP_XOR_QUAD_CurrentVersionRun_6c44 {
  strings:
    $key_6c44 = { 3f 2b [2] 1b 25 [2] 30 09 [2] 1e 2b [2] 0a 30 [2] 05 2a [2] 1b 37 [2] 19 36 [2] 02 30 [2] 1e 37 [2] 02 18 }

  condition:
    any of them
}