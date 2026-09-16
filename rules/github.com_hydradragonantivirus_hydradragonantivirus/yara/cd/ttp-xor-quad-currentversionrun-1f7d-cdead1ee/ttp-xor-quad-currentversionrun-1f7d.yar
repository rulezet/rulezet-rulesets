rule TTP_XOR_QUAD_CurrentVersionRun_1f7d {
  strings:
    $key_1f7d = { 4c 12 [2] 68 1c [2] 43 30 [2] 6d 12 [2] 79 09 [2] 76 13 [2] 68 0e [2] 6a 0f [2] 71 09 [2] 6d 0e [2] 71 21 }

  condition:
    any of them
}