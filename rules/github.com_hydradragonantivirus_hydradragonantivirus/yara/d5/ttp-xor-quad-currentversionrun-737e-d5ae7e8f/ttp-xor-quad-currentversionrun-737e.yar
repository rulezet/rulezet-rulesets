rule TTP_XOR_QUAD_CurrentVersionRun_737e {
  strings:
    $key_737e = { 20 11 [2] 04 1f [2] 2f 33 [2] 01 11 [2] 15 0a [2] 1a 10 [2] 04 0d [2] 06 0c [2] 1d 0a [2] 01 0d [2] 1d 22 }

  condition:
    any of them
}