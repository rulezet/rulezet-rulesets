rule TTP_XOR_QUAD_CurrentVersionRun_624e {
  strings:
    $key_624e = { 31 21 [2] 15 2f [2] 3e 03 [2] 10 21 [2] 04 3a [2] 0b 20 [2] 15 3d [2] 17 3c [2] 0c 3a [2] 10 3d [2] 0c 12 }

  condition:
    any of them
}