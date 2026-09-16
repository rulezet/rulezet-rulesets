rule TTP_XOR_QUAD_CurrentVersionRun_642e {
  strings:
    $key_642e = { 37 41 [2] 13 4f [2] 38 63 [2] 16 41 [2] 02 5a [2] 0d 40 [2] 13 5d [2] 11 5c [2] 0a 5a [2] 16 5d [2] 0a 72 }

  condition:
    any of them
}