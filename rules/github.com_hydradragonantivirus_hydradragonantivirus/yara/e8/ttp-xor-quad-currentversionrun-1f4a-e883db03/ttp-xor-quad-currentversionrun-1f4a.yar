rule TTP_XOR_QUAD_CurrentVersionRun_1f4a {
  strings:
    $key_1f4a = { 4c 25 [2] 68 2b [2] 43 07 [2] 6d 25 [2] 79 3e [2] 76 24 [2] 68 39 [2] 6a 38 [2] 71 3e [2] 6d 39 [2] 71 16 }

  condition:
    any of them
}