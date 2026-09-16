rule TTP_XOR_QUAD_CurrentVersionRun_3c4e {
  strings:
    $key_3c4e = { 6f 21 [2] 4b 2f [2] 60 03 [2] 4e 21 [2] 5a 3a [2] 55 20 [2] 4b 3d [2] 49 3c [2] 52 3a [2] 4e 3d [2] 52 12 }

  condition:
    any of them
}