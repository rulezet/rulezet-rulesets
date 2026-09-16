rule TTP_XOR_QUAD_CurrentVersionRun_fe7c {
  strings:
    $key_fe7c = { ad 13 [2] 89 1d [2] a2 31 [2] 8c 13 [2] 98 08 [2] 97 12 [2] 89 0f [2] 8b 0e [2] 90 08 [2] 8c 0f [2] 90 20 }

  condition:
    any of them
}