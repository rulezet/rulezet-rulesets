rule TTP_XOR_QUAD_CurrentVersionRun_574e {
  strings:
    $key_574e = { 04 21 [2] 20 2f [2] 0b 03 [2] 25 21 [2] 31 3a [2] 3e 20 [2] 20 3d [2] 22 3c [2] 39 3a [2] 25 3d [2] 39 12 }

  condition:
    any of them
}