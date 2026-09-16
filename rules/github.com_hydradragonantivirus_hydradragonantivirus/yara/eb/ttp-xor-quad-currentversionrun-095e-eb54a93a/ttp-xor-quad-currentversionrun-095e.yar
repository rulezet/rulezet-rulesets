rule TTP_XOR_QUAD_CurrentVersionRun_095e {
  strings:
    $key_095e = { 5a 31 [2] 7e 3f [2] 55 13 [2] 7b 31 [2] 6f 2a [2] 60 30 [2] 7e 2d [2] 7c 2c [2] 67 2a [2] 7b 2d [2] 67 02 }

  condition:
    any of them
}