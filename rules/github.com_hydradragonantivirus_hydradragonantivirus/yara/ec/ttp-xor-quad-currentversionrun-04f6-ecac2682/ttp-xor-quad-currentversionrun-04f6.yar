rule TTP_XOR_QUAD_CurrentVersionRun_04f6 {
  strings:
    $key_04f6 = { 57 99 [2] 73 97 [2] 58 bb [2] 76 99 [2] 62 82 [2] 6d 98 [2] 73 85 [2] 71 84 [2] 6a 82 [2] 76 85 [2] 6a aa }

  condition:
    any of them
}