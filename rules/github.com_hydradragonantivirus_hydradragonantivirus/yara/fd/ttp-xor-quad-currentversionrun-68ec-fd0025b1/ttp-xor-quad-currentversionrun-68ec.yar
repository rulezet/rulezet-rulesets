rule TTP_XOR_QUAD_CurrentVersionRun_68ec {
  strings:
    $key_68ec = { 3b 83 [2] 1f 8d [2] 34 a1 [2] 1a 83 [2] 0e 98 [2] 01 82 [2] 1f 9f [2] 1d 9e [2] 06 98 [2] 1a 9f [2] 06 b0 }

  condition:
    any of them
}