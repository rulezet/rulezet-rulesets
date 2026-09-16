rule TTP_XOR_QUAD_CurrentVersionRun_4e05 {
  strings:
    $key_4e05 = { 1d 6a [2] 39 64 [2] 12 48 [2] 3c 6a [2] 28 71 [2] 27 6b [2] 39 76 [2] 3b 77 [2] 20 71 [2] 3c 76 [2] 20 59 }

  condition:
    any of them
}