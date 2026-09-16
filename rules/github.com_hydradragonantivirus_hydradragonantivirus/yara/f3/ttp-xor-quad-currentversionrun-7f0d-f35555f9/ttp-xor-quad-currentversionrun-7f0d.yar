rule TTP_XOR_QUAD_CurrentVersionRun_7f0d {
  strings:
    $key_7f0d = { 2c 62 [2] 08 6c [2] 23 40 [2] 0d 62 [2] 19 79 [2] 16 63 [2] 08 7e [2] 0a 7f [2] 11 79 [2] 0d 7e [2] 11 51 }

  condition:
    any of them
}