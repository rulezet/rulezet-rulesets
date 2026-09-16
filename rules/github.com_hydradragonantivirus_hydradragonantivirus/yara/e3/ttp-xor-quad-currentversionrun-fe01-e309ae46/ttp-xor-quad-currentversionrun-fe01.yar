rule TTP_XOR_QUAD_CurrentVersionRun_fe01 {
  strings:
    $key_fe01 = { ad 6e [2] 89 60 [2] a2 4c [2] 8c 6e [2] 98 75 [2] 97 6f [2] 89 72 [2] 8b 73 [2] 90 75 [2] 8c 72 [2] 90 5d }

  condition:
    any of them
}