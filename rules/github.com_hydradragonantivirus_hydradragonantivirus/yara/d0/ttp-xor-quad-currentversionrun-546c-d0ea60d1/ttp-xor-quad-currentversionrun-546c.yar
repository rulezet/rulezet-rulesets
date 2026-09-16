rule TTP_XOR_QUAD_CurrentVersionRun_546c {
  strings:
    $key_546c = { 07 03 [2] 23 0d [2] 08 21 [2] 26 03 [2] 32 18 [2] 3d 02 [2] 23 1f [2] 21 1e [2] 3a 18 [2] 26 1f [2] 3a 30 }

  condition:
    any of them
}