rule TTP_XOR_QUAD_CurrentVersionRun_5e0a {
  strings:
    $key_5e0a = { 0d 65 [2] 29 6b [2] 02 47 [2] 2c 65 [2] 38 7e [2] 37 64 [2] 29 79 [2] 2b 78 [2] 30 7e [2] 2c 79 [2] 30 56 }

  condition:
    any of them
}