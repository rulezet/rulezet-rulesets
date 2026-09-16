rule TTP_XOR_QUAD_CurrentVersionRun_187e {
  strings:
    $key_187e = { 4b 11 [2] 6f 1f [2] 44 33 [2] 6a 11 [2] 7e 0a [2] 71 10 [2] 6f 0d [2] 6d 0c [2] 76 0a [2] 6a 0d [2] 76 22 }

  condition:
    any of them
}