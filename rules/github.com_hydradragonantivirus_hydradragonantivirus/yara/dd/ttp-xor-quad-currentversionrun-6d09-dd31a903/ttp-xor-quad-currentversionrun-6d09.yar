rule TTP_XOR_QUAD_CurrentVersionRun_6d09 {
  strings:
    $key_6d09 = { 3e 66 [2] 1a 68 [2] 31 44 [2] 1f 66 [2] 0b 7d [2] 04 67 [2] 1a 7a [2] 18 7b [2] 03 7d [2] 1f 7a [2] 03 55 }

  condition:
    any of them
}