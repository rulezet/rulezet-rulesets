rule TTP_XOR_QUAD_CurrentVersionRun_fe71 {
  strings:
    $key_fe71 = { ad 1e [2] 89 10 [2] a2 3c [2] 8c 1e [2] 98 05 [2] 97 1f [2] 89 02 [2] 8b 03 [2] 90 05 [2] 8c 02 [2] 90 2d }

  condition:
    any of them
}