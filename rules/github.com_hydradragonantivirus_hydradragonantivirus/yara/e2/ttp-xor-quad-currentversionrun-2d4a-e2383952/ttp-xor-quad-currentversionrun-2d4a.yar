rule TTP_XOR_QUAD_CurrentVersionRun_2d4a {
  strings:
    $key_2d4a = { 7e 25 [2] 5a 2b [2] 71 07 [2] 5f 25 [2] 4b 3e [2] 44 24 [2] 5a 39 [2] 58 38 [2] 43 3e [2] 5f 39 [2] 43 16 }

  condition:
    any of them
}