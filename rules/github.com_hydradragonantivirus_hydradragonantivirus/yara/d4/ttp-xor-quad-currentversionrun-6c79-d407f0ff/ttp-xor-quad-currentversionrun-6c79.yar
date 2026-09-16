rule TTP_XOR_QUAD_CurrentVersionRun_6c79 {
  strings:
    $key_6c79 = { 3f 16 [2] 1b 18 [2] 30 34 [2] 1e 16 [2] 0a 0d [2] 05 17 [2] 1b 0a [2] 19 0b [2] 02 0d [2] 1e 0a [2] 02 25 }

  condition:
    any of them
}