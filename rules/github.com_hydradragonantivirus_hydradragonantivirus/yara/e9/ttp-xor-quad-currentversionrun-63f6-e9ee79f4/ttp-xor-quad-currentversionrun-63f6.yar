rule TTP_XOR_QUAD_CurrentVersionRun_63f6 {
  strings:
    $key_63f6 = { 30 99 [2] 14 97 [2] 3f bb [2] 11 99 [2] 05 82 [2] 0a 98 [2] 14 85 [2] 16 84 [2] 0d 82 [2] 11 85 [2] 0d aa }

  condition:
    any of them
}