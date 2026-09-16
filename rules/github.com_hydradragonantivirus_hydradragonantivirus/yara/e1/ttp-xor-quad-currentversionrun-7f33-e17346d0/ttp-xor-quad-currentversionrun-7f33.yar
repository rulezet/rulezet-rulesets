rule TTP_XOR_QUAD_CurrentVersionRun_7f33 {
  strings:
    $key_7f33 = { 2c 5c [2] 08 52 [2] 23 7e [2] 0d 5c [2] 19 47 [2] 16 5d [2] 08 40 [2] 0a 41 [2] 11 47 [2] 0d 40 [2] 11 6f }

  condition:
    any of them
}