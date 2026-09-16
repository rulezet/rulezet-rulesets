rule TTP_XOR_QUAD_CurrentVersionRun_1f1d {
  strings:
    $key_1f1d = { 4c 72 [2] 68 7c [2] 43 50 [2] 6d 72 [2] 79 69 [2] 76 73 [2] 68 6e [2] 6a 6f [2] 71 69 [2] 6d 6e [2] 71 41 }

  condition:
    any of them
}