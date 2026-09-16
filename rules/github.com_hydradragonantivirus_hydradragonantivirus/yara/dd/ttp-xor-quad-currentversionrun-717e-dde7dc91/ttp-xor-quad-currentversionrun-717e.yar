rule TTP_XOR_QUAD_CurrentVersionRun_717e {
  strings:
    $key_717e = { 22 11 [2] 06 1f [2] 2d 33 [2] 03 11 [2] 17 0a [2] 18 10 [2] 06 0d [2] 04 0c [2] 1f 0a [2] 03 0d [2] 1f 22 }

  condition:
    any of them
}