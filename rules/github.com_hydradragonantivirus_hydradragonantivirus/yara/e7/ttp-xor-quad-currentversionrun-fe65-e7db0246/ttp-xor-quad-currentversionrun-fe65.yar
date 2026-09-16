rule TTP_XOR_QUAD_CurrentVersionRun_fe65 {
  strings:
    $key_fe65 = { ad 0a [2] 89 04 [2] a2 28 [2] 8c 0a [2] 98 11 [2] 97 0b [2] 89 16 [2] 8b 17 [2] 90 11 [2] 8c 16 [2] 90 39 }

  condition:
    any of them
}