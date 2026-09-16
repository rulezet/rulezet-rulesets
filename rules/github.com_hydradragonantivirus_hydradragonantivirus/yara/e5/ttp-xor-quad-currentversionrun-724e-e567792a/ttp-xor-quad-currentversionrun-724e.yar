rule TTP_XOR_QUAD_CurrentVersionRun_724e {
  strings:
    $key_724e = { 21 21 [2] 05 2f [2] 2e 03 [2] 00 21 [2] 14 3a [2] 1b 20 [2] 05 3d [2] 07 3c [2] 1c 3a [2] 00 3d [2] 1c 12 }

  condition:
    any of them
}