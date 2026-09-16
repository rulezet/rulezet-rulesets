rule TTP_XOR_QUAD_CurrentVersionRun_3e05 {
  strings:
    $key_3e05 = { 6d 6a [2] 49 64 [2] 62 48 [2] 4c 6a [2] 58 71 [2] 57 6b [2] 49 76 [2] 4b 77 [2] 50 71 [2] 4c 76 [2] 50 59 }

  condition:
    any of them
}