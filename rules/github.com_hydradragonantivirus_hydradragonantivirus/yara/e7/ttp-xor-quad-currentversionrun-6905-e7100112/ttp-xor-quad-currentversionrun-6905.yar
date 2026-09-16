rule TTP_XOR_QUAD_CurrentVersionRun_6905 {
  strings:
    $key_6905 = { 3a 6a [2] 1e 64 [2] 35 48 [2] 1b 6a [2] 0f 71 [2] 00 6b [2] 1e 76 [2] 1c 77 [2] 07 71 [2] 1b 76 [2] 07 59 }

  condition:
    any of them
}