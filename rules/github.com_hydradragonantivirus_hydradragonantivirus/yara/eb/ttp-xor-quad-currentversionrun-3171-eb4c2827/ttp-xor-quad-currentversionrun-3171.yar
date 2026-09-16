rule TTP_XOR_QUAD_CurrentVersionRun_3171 {
  strings:
    $key_3171 = { 62 1e [2] 46 10 [2] 6d 3c [2] 43 1e [2] 57 05 [2] 58 1f [2] 46 02 [2] 44 03 [2] 5f 05 [2] 43 02 [2] 5f 2d }

  condition:
    any of them
}