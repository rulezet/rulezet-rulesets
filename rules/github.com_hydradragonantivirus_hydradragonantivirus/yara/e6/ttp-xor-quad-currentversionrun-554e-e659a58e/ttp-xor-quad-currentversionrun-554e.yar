rule TTP_XOR_QUAD_CurrentVersionRun_554e {
  strings:
    $key_554e = { 06 21 [2] 22 2f [2] 09 03 [2] 27 21 [2] 33 3a [2] 3c 20 [2] 22 3d [2] 20 3c [2] 3b 3a [2] 27 3d [2] 3b 12 }

  condition:
    any of them
}