rule TTP_XOR_QUAD_CurrentVersionRun_5e2f {
  strings:
    $key_5e2f = { 0d 40 [2] 29 4e [2] 02 62 [2] 2c 40 [2] 38 5b [2] 37 41 [2] 29 5c [2] 2b 5d [2] 30 5b [2] 2c 5c [2] 30 73 }

  condition:
    any of them
}