rule TTP_XOR_QUAD_CurrentVersionRun_73f6 {
  strings:
    $key_73f6 = { 20 99 [2] 04 97 [2] 2f bb [2] 01 99 [2] 15 82 [2] 1a 98 [2] 04 85 [2] 06 84 [2] 1d 82 [2] 01 85 [2] 1d aa }

  condition:
    any of them
}