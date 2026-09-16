rule TTP_XOR_QUAD_CurrentVersionRun_2a4a {
  strings:
    $key_2a4a = { 79 25 [2] 5d 2b [2] 76 07 [2] 58 25 [2] 4c 3e [2] 43 24 [2] 5d 39 [2] 5f 38 [2] 44 3e [2] 58 39 [2] 44 16 }

  condition:
    any of them
}