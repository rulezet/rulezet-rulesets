rule TTP_XOR_QUAD_CurrentVersionRun_fe63 {
  strings:
    $key_fe63 = { ad 0c [2] 89 02 [2] a2 2e [2] 8c 0c [2] 98 17 [2] 97 0d [2] 89 10 [2] 8b 11 [2] 90 17 [2] 8c 10 [2] 90 3f }

  condition:
    any of them
}