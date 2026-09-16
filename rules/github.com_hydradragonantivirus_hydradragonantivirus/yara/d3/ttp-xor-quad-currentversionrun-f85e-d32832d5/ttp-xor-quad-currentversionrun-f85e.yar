rule TTP_XOR_QUAD_CurrentVersionRun_f85e {
  strings:
    $key_f85e = { ab 31 [2] 8f 3f [2] a4 13 [2] 8a 31 [2] 9e 2a [2] 91 30 [2] 8f 2d [2] 8d 2c [2] 96 2a [2] 8a 2d [2] 96 02 }

  condition:
    any of them
}