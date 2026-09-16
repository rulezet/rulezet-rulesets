rule TTP_XOR_QUAD_CurrentVersionRun_fe5a {
  strings:
    $key_fe5a = { ad 35 [2] 89 3b [2] a2 17 [2] 8c 35 [2] 98 2e [2] 97 34 [2] 89 29 [2] 8b 28 [2] 90 2e [2] 8c 29 [2] 90 06 }

  condition:
    any of them
}