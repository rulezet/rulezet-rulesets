rule TTP_XOR_QUAD_CurrentVersionRun_354e {
  strings:
    $key_354e = { 66 21 [2] 42 2f [2] 69 03 [2] 47 21 [2] 53 3a [2] 5c 20 [2] 42 3d [2] 40 3c [2] 5b 3a [2] 47 3d [2] 5b 12 }

  condition:
    any of them
}