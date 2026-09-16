rule TTP_XOR_QUAD_CurrentVersionRun_fe74 {
  strings:
    $key_fe74 = { ad 1b [2] 89 15 [2] a2 39 [2] 8c 1b [2] 98 00 [2] 97 1a [2] 89 07 [2] 8b 06 [2] 90 00 [2] 8c 07 [2] 90 28 }

  condition:
    any of them
}