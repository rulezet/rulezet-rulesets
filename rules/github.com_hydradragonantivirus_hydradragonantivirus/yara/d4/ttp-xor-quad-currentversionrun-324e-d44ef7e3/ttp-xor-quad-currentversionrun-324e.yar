rule TTP_XOR_QUAD_CurrentVersionRun_324e {
  strings:
    $key_324e = { 61 21 [2] 45 2f [2] 6e 03 [2] 40 21 [2] 54 3a [2] 5b 20 [2] 45 3d [2] 47 3c [2] 5c 3a [2] 40 3d [2] 5c 12 }

  condition:
    any of them
}