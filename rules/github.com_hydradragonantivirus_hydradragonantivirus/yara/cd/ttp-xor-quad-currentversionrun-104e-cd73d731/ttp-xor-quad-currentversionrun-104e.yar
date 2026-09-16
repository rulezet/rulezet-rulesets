rule TTP_XOR_QUAD_CurrentVersionRun_104e {
  strings:
    $key_104e = { 43 21 [2] 67 2f [2] 4c 03 [2] 62 21 [2] 76 3a [2] 79 20 [2] 67 3d [2] 65 3c [2] 7e 3a [2] 62 3d [2] 7e 12 }

  condition:
    any of them
}