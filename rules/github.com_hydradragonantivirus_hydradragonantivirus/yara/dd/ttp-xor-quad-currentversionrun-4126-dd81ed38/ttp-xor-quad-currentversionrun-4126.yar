rule TTP_XOR_QUAD_CurrentVersionRun_4126 {
  strings:
    $key_4126 = { 12 49 [2] 36 47 [2] 1d 6b [2] 33 49 [2] 27 52 [2] 28 48 [2] 36 55 [2] 34 54 [2] 2f 52 [2] 33 55 [2] 2f 7a }

  condition:
    any of them
}