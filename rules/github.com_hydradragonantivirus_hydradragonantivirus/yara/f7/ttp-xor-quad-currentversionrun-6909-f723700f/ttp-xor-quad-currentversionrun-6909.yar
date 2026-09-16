rule TTP_XOR_QUAD_CurrentVersionRun_6909 {
  strings:
    $key_6909 = { 3a 66 [2] 1e 68 [2] 35 44 [2] 1b 66 [2] 0f 7d [2] 00 67 [2] 1e 7a [2] 1c 7b [2] 07 7d [2] 1b 7a [2] 07 55 }

  condition:
    any of them
}