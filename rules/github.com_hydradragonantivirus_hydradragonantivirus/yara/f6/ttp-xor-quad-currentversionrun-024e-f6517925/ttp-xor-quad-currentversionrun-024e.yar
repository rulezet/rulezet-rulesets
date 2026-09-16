rule TTP_XOR_QUAD_CurrentVersionRun_024e {
  strings:
    $key_024e = { 51 21 [2] 75 2f [2] 5e 03 [2] 70 21 [2] 64 3a [2] 6b 20 [2] 75 3d [2] 77 3c [2] 6c 3a [2] 70 3d [2] 6c 12 }

  condition:
    any of them
}