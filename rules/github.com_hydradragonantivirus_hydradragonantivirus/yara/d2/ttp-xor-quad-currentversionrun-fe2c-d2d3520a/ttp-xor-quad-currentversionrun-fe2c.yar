rule TTP_XOR_QUAD_CurrentVersionRun_fe2c {
  strings:
    $key_fe2c = { ad 43 [2] 89 4d [2] a2 61 [2] 8c 43 [2] 98 58 [2] 97 42 [2] 89 5f [2] 8b 5e [2] 90 58 [2] 8c 5f [2] 90 70 }

  condition:
    any of them
}