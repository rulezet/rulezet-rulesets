rule TTP_XOR_QUAD_CurrentVersionRun_195e {
  strings:
    $key_195e = { 4a 31 [2] 6e 3f [2] 45 13 [2] 6b 31 [2] 7f 2a [2] 70 30 [2] 6e 2d [2] 6c 2c [2] 77 2a [2] 6b 2d [2] 77 02 }

  condition:
    any of them
}