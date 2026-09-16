rule TTP_XOR_QUAD_CurrentVersionRun_fe5e {
  strings:
    $key_fe5e = { ad 31 [2] 89 3f [2] a2 13 [2] 8c 31 [2] 98 2a [2] 97 30 [2] 89 2d [2] 8b 2c [2] 90 2a [2] 8c 2d [2] 90 02 }

  condition:
    any of them
}