rule TTP_XOR_QUAD_CurrentVersionRun_fe4c {
  strings:
    $key_fe4c = { ad 23 [2] 89 2d [2] a2 01 [2] 8c 23 [2] 98 38 [2] 97 22 [2] 89 3f [2] 8b 3e [2] 90 38 [2] 8c 3f [2] 90 10 }

  condition:
    any of them
}