rule TTP_XOR_QUAD_CurrentVersionRun_1b05 {
  strings:
    $key_1b05 = { 48 6a [2] 6c 64 [2] 47 48 [2] 69 6a [2] 7d 71 [2] 72 6b [2] 6c 76 [2] 6e 77 [2] 75 71 [2] 69 76 [2] 75 59 }

  condition:
    any of them
}