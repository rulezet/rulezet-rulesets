rule TTP_XOR_QUAD_CurrentVersionRun_1ffc {
  strings:
    $key_1ffc = { 4c 93 [2] 68 9d [2] 43 b1 [2] 6d 93 [2] 79 88 [2] 76 92 [2] 68 8f [2] 6a 8e [2] 71 88 [2] 6d 8f [2] 71 a0 }

  condition:
    any of them
}