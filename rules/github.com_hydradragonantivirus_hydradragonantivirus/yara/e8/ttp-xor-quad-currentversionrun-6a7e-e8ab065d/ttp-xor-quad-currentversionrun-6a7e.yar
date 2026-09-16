rule TTP_XOR_QUAD_CurrentVersionRun_6a7e {
  strings:
    $key_6a7e = { 39 11 [2] 1d 1f [2] 36 33 [2] 18 11 [2] 0c 0a [2] 03 10 [2] 1d 0d [2] 1f 0c [2] 04 0a [2] 18 0d [2] 04 22 }

  condition:
    any of them
}