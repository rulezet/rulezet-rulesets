rule TTP_XOR_QUAD_CurrentVersionRun_1f51 {
  strings:
    $key_1f51 = { 4c 3e [2] 68 30 [2] 43 1c [2] 6d 3e [2] 79 25 [2] 76 3f [2] 68 22 [2] 6a 23 [2] 71 25 [2] 6d 22 [2] 71 0d }

  condition:
    any of them
}