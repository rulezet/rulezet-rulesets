rule TTP_XOR_QUAD_CurrentVersionRun_5e0d {
  strings:
    $key_5e0d = { 0d 62 [2] 29 6c [2] 02 40 [2] 2c 62 [2] 38 79 [2] 37 63 [2] 29 7e [2] 2b 7f [2] 30 79 [2] 2c 7e [2] 30 51 }

  condition:
    any of them
}