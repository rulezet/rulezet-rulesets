rule TTP_XOR_QUAD_CurrentVersionRun_57f6 {
  strings:
    $key_57f6 = { 04 99 [2] 20 97 [2] 0b bb [2] 25 99 [2] 31 82 [2] 3e 98 [2] 20 85 [2] 22 84 [2] 39 82 [2] 25 85 [2] 39 aa }

  condition:
    any of them
}