rule TTP_XOR_QUAD_CurrentVersionRun_632e {
  strings:
    $key_632e = { 30 41 [2] 14 4f [2] 3f 63 [2] 11 41 [2] 05 5a [2] 0a 40 [2] 14 5d [2] 16 5c [2] 0d 5a [2] 11 5d [2] 0d 72 }

  condition:
    any of them
}