rule TTP_XOR_QUAD_CurrentVersionRun_7f2d {
  strings:
    $key_7f2d = { 2c 42 [2] 08 4c [2] 23 60 [2] 0d 42 [2] 19 59 [2] 16 43 [2] 08 5e [2] 0a 5f [2] 11 59 [2] 0d 5e [2] 11 71 }

  condition:
    any of them
}