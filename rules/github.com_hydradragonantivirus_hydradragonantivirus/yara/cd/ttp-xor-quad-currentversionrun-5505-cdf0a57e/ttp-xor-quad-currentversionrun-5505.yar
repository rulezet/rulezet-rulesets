rule TTP_XOR_QUAD_CurrentVersionRun_5505 {
  strings:
    $key_5505 = { 06 6a [2] 22 64 [2] 09 48 [2] 27 6a [2] 33 71 [2] 3c 6b [2] 22 76 [2] 20 77 [2] 3b 71 [2] 27 76 [2] 3b 59 }

  condition:
    any of them
}