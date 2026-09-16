rule TTP_XOR_QUAD_CurrentVersionRun_fe17 {
  strings:
    $key_fe17 = { ad 78 [2] 89 76 [2] a2 5a [2] 8c 78 [2] 98 63 [2] 97 79 [2] 89 64 [2] 8b 65 [2] 90 63 [2] 8c 64 [2] 90 4b }

  condition:
    any of them
}