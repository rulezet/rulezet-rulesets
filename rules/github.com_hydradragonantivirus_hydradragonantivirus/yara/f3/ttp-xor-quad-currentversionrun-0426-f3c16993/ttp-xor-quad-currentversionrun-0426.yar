rule TTP_XOR_QUAD_CurrentVersionRun_0426 {
  strings:
    $key_0426 = { 57 49 [2] 73 47 [2] 58 6b [2] 76 49 [2] 62 52 [2] 6d 48 [2] 73 55 [2] 71 54 [2] 6a 52 [2] 76 55 [2] 6a 7a }

  condition:
    any of them
}