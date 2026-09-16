rule TTP_XOR_QUAD_CurrentVersionRun_fe41 {
  strings:
    $key_fe41 = { ad 2e [2] 89 20 [2] a2 0c [2] 8c 2e [2] 98 35 [2] 97 2f [2] 89 32 [2] 8b 33 [2] 90 35 [2] 8c 32 [2] 90 1d }

  condition:
    any of them
}