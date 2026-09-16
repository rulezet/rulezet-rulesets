rule TTP_XOR_QUAD_CurrentVersionRun_75e5 {
  strings:
    $key_75e5 = { 26 8a [2] 02 84 [2] 29 a8 [2] 07 8a [2] 13 91 [2] 1c 8b [2] 02 96 [2] 00 97 [2] 1b 91 [2] 07 96 [2] 1b b9 }

  condition:
    any of them
}