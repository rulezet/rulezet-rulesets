rule TTP_XOR_QUAD_CurrentVersionRun_48ed {
  strings:
    $key_48ed = { 1b 82 [2] 3f 8c [2] 14 a0 [2] 3a 82 [2] 2e 99 [2] 21 83 [2] 3f 9e [2] 3d 9f [2] 26 99 [2] 3a 9e [2] 26 b1 }

  condition:
    any of them
}