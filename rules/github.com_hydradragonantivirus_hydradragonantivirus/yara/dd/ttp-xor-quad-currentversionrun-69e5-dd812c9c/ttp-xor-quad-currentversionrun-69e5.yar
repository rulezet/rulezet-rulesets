rule TTP_XOR_QUAD_CurrentVersionRun_69e5 {
  strings:
    $key_69e5 = { 3a 8a [2] 1e 84 [2] 35 a8 [2] 1b 8a [2] 0f 91 [2] 00 8b [2] 1e 96 [2] 1c 97 [2] 07 91 [2] 1b 96 [2] 07 b9 }

  condition:
    any of them
}