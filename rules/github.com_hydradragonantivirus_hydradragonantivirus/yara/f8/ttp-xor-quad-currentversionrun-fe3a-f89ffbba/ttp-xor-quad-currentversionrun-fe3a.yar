rule TTP_XOR_QUAD_CurrentVersionRun_fe3a {
  strings:
    $key_fe3a = { ad 55 [2] 89 5b [2] a2 77 [2] 8c 55 [2] 98 4e [2] 97 54 [2] 89 49 [2] 8b 48 [2] 90 4e [2] 8c 49 [2] 90 66 }

  condition:
    any of them
}