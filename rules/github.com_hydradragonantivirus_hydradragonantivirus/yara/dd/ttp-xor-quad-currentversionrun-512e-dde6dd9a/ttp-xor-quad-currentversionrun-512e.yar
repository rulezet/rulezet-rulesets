rule TTP_XOR_QUAD_CurrentVersionRun_512e {
  strings:
    $key_512e = { 02 41 [2] 26 4f [2] 0d 63 [2] 23 41 [2] 37 5a [2] 38 40 [2] 26 5d [2] 24 5c [2] 3f 5a [2] 23 5d [2] 3f 72 }

  condition:
    any of them
}