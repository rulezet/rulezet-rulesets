rule TTP_XOR_QUAD_CurrentVersionRun_6a36 {
  strings:
    $key_6a36 = { 39 59 [2] 1d 57 [2] 36 7b [2] 18 59 [2] 0c 42 [2] 03 58 [2] 1d 45 [2] 1f 44 [2] 04 42 [2] 18 45 [2] 04 6a }

  condition:
    any of them
}