rule TTP_XOR_QUAD_CurrentVersionRun_1ffd {
  strings:
    $key_1ffd = { 4c 92 [2] 68 9c [2] 43 b0 [2] 6d 92 [2] 79 89 [2] 76 93 [2] 68 8e [2] 6a 8f [2] 71 89 [2] 6d 8e [2] 71 a1 }

  condition:
    any of them
}