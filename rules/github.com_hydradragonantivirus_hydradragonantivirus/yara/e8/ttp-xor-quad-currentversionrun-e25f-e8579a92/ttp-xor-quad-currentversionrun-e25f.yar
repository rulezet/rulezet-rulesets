rule TTP_XOR_QUAD_CurrentVersionRun_e25f {
  strings:
    $key_e25f = { b1 30 [2] 95 3e [2] be 12 [2] 90 30 [2] 84 2b [2] 8b 31 [2] 95 2c [2] 97 2d [2] 8c 2b [2] 90 2c [2] 8c 03 }

  condition:
    any of them
}