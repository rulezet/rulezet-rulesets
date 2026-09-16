rule TTP_XOR_QUAD_CurrentVersionRun_4871 {
  strings:
    $key_4871 = { 1b 1e [2] 3f 10 [2] 14 3c [2] 3a 1e [2] 2e 05 [2] 21 1f [2] 3f 02 [2] 3d 03 [2] 26 05 [2] 3a 02 [2] 26 2d }

  condition:
    any of them
}