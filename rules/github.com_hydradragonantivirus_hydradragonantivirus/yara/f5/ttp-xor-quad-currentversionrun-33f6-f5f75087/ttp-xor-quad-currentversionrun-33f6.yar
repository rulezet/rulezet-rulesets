rule TTP_XOR_QUAD_CurrentVersionRun_33f6 {
  strings:
    $key_33f6 = { 60 99 [2] 44 97 [2] 6f bb [2] 41 99 [2] 55 82 [2] 5a 98 [2] 44 85 [2] 46 84 [2] 5d 82 [2] 41 85 [2] 5d aa }

  condition:
    any of them
}