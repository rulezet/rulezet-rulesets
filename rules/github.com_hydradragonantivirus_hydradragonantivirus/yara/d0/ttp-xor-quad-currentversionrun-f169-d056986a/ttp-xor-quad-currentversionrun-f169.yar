rule TTP_XOR_QUAD_CurrentVersionRun_f169 {
  strings:
    $key_f169 = { a2 06 [2] 86 08 [2] ad 24 [2] 83 06 [2] 97 1d [2] 98 07 [2] 86 1a [2] 84 1b [2] 9f 1d [2] 83 1a [2] 9f 35 }

  condition:
    any of them
}