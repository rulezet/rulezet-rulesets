rule TTP_XOR_QUAD_CurrentVersionRun_fe3b {
  strings:
    $key_fe3b = { ad 54 [2] 89 5a [2] a2 76 [2] 8c 54 [2] 98 4f [2] 97 55 [2] 89 48 [2] 8b 49 [2] 90 4f [2] 8c 48 [2] 90 67 }

  condition:
    any of them
}