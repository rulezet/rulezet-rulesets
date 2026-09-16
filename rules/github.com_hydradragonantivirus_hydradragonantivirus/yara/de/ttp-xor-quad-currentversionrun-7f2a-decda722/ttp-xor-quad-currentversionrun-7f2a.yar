rule TTP_XOR_QUAD_CurrentVersionRun_7f2a {
  strings:
    $key_7f2a = { 2c 45 [2] 08 4b [2] 23 67 [2] 0d 45 [2] 19 5e [2] 16 44 [2] 08 59 [2] 0a 58 [2] 11 5e [2] 0d 59 [2] 11 76 }

  condition:
    any of them
}