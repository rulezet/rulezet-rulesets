rule TTP_XOR_QUAD_CurrentVersionRun_67f6 {
  strings:
    $key_67f6 = { 34 99 [2] 10 97 [2] 3b bb [2] 15 99 [2] 01 82 [2] 0e 98 [2] 10 85 [2] 12 84 [2] 09 82 [2] 15 85 [2] 09 aa }

  condition:
    any of them
}