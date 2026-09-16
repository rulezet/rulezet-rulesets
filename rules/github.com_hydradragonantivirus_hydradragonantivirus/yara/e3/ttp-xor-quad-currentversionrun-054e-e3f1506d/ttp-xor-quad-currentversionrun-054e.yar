rule TTP_XOR_QUAD_CurrentVersionRun_054e {
  strings:
    $key_054e = { 56 21 [2] 72 2f [2] 59 03 [2] 77 21 [2] 63 3a [2] 6c 20 [2] 72 3d [2] 70 3c [2] 6b 3a [2] 77 3d [2] 6b 12 }

  condition:
    any of them
}