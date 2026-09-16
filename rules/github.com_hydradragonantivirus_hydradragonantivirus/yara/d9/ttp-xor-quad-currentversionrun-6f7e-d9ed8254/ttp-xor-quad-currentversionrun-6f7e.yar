rule TTP_XOR_QUAD_CurrentVersionRun_6f7e {
  strings:
    $key_6f7e = { 3c 11 [2] 18 1f [2] 33 33 [2] 1d 11 [2] 09 0a [2] 06 10 [2] 18 0d [2] 1a 0c [2] 01 0a [2] 1d 0d [2] 01 22 }

  condition:
    any of them
}