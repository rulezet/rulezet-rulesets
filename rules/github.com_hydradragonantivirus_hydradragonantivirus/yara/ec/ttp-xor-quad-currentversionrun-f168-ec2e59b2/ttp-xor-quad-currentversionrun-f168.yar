rule TTP_XOR_QUAD_CurrentVersionRun_f168 {
  strings:
    $key_f168 = { a2 07 [2] 86 09 [2] ad 25 [2] 83 07 [2] 97 1c [2] 98 06 [2] 86 1b [2] 84 1a [2] 9f 1c [2] 83 1b [2] 9f 34 }

  condition:
    any of them
}