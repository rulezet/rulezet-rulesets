rule TTP_XOR_QUAD_CurrentVersionRun_fe33 {
  strings:
    $key_fe33 = { ad 5c [2] 89 52 [2] a2 7e [2] 8c 5c [2] 98 47 [2] 97 5d [2] 89 40 [2] 8b 41 [2] 90 47 [2] 8c 40 [2] 90 6f }

  condition:
    any of them
}