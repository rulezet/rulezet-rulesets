rule TTP_XOR_QUAD_CurrentVersionRun_7505 {
  strings:
    $key_7505 = { 26 6a [2] 02 64 [2] 29 48 [2] 07 6a [2] 13 71 [2] 1c 6b [2] 02 76 [2] 00 77 [2] 1b 71 [2] 07 76 [2] 1b 59 }

  condition:
    any of them
}