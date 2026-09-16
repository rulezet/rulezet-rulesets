rule TTP_XOR_QUAD_CurrentVersionRun_7c34 {
  strings:
    $key_7c34 = { 2f 5b [2] 0b 55 [2] 20 79 [2] 0e 5b [2] 1a 40 [2] 15 5a [2] 0b 47 [2] 09 46 [2] 12 40 [2] 0e 47 [2] 12 68 }

  condition:
    any of them
}