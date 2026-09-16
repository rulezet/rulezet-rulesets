rule TTP_XOR_QUAD_CurrentVersionRun_005e {
  strings:
    $key_005e = { 53 31 [2] 77 3f [2] 5c 13 [2] 72 31 [2] 66 2a [2] 69 30 [2] 77 2d [2] 75 2c [2] 6e 2a [2] 72 2d [2] 6e 02 }

  condition:
    any of them
}