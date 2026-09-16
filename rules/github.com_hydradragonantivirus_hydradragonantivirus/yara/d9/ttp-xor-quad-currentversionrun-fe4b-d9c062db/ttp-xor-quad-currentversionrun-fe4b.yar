rule TTP_XOR_QUAD_CurrentVersionRun_fe4b {
  strings:
    $key_fe4b = { ad 24 [2] 89 2a [2] a2 06 [2] 8c 24 [2] 98 3f [2] 97 25 [2] 89 38 [2] 8b 39 [2] 90 3f [2] 8c 38 [2] 90 17 }

  condition:
    any of them
}