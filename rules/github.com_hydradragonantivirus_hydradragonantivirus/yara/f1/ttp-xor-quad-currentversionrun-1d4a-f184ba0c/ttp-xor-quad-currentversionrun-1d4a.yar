rule TTP_XOR_QUAD_CurrentVersionRun_1d4a {
  strings:
    $key_1d4a = { 4e 25 [2] 6a 2b [2] 41 07 [2] 6f 25 [2] 7b 3e [2] 74 24 [2] 6a 39 [2] 68 38 [2] 73 3e [2] 6f 39 [2] 73 16 }

  condition:
    any of them
}