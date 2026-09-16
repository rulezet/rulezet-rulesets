rule TTP_XOR_QUAD_CurrentVersionRun_f166 {
  strings:
    $key_f166 = { a2 09 [2] 86 07 [2] ad 2b [2] 83 09 [2] 97 12 [2] 98 08 [2] 86 15 [2] 84 14 [2] 9f 12 [2] 83 15 [2] 9f 3a }

  condition:
    any of them
}