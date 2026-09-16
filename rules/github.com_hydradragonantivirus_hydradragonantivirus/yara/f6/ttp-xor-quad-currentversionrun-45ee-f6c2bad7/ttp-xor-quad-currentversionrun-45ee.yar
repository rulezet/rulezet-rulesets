rule TTP_XOR_QUAD_CurrentVersionRun_45ee {
  strings:
    $key_45ee = { 16 81 [2] 32 8f [2] 19 a3 [2] 37 81 [2] 23 9a [2] 2c 80 [2] 32 9d [2] 30 9c [2] 2b 9a [2] 37 9d [2] 2b b2 }

  condition:
    any of them
}