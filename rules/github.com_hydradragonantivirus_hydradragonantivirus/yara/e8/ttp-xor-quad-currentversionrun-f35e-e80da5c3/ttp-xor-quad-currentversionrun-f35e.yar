rule TTP_XOR_QUAD_CurrentVersionRun_f35e {
  strings:
    $key_f35e = { a0 31 [2] 84 3f [2] af 13 [2] 81 31 [2] 95 2a [2] 9a 30 [2] 84 2d [2] 86 2c [2] 9d 2a [2] 81 2d [2] 9d 02 }

  condition:
    any of them
}