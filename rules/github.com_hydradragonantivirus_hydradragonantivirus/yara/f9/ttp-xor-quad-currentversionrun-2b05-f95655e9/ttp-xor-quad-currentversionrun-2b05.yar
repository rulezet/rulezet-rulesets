rule TTP_XOR_QUAD_CurrentVersionRun_2b05 {
  strings:
    $key_2b05 = { 78 6a [2] 5c 64 [2] 77 48 [2] 59 6a [2] 4d 71 [2] 42 6b [2] 5c 76 [2] 5e 77 [2] 45 71 [2] 59 76 [2] 45 59 }

  condition:
    any of them
}