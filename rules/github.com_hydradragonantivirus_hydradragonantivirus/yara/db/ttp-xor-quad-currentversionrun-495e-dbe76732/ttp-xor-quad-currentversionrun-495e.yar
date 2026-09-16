rule TTP_XOR_QUAD_CurrentVersionRun_495e {
  strings:
    $key_495e = { 1a 31 [2] 3e 3f [2] 15 13 [2] 3b 31 [2] 2f 2a [2] 20 30 [2] 3e 2d [2] 3c 2c [2] 27 2a [2] 3b 2d [2] 27 02 }

  condition:
    any of them
}