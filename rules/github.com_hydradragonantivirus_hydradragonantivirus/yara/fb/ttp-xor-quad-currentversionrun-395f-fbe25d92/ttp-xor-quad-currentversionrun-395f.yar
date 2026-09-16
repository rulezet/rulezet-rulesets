rule TTP_XOR_QUAD_CurrentVersionRun_395f {
  strings:
    $key_395f = { 6a 30 [2] 4e 3e [2] 65 12 [2] 4b 30 [2] 5f 2b [2] 50 31 [2] 4e 2c [2] 4c 2d [2] 57 2b [2] 4b 2c [2] 57 03 }

  condition:
    any of them
}