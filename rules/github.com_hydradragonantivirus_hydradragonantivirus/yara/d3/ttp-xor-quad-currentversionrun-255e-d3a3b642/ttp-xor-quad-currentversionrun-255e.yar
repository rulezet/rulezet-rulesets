rule TTP_XOR_QUAD_CurrentVersionRun_255e {
  strings:
    $key_255e = { 76 31 [2] 52 3f [2] 79 13 [2] 57 31 [2] 43 2a [2] 4c 30 [2] 52 2d [2] 50 2c [2] 4b 2a [2] 57 2d [2] 4b 02 }

  condition:
    any of them
}