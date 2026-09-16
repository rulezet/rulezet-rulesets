rule TTP_XOR_QUAD_CurrentVersionRun_07f6 {
  strings:
    $key_07f6 = { 54 99 [2] 70 97 [2] 5b bb [2] 75 99 [2] 61 82 [2] 6e 98 [2] 70 85 [2] 72 84 [2] 69 82 [2] 75 85 [2] 69 aa }

  condition:
    any of them
}