rule TTP_XOR_QUAD_CurrentVersionRun_1a5a {
  strings:
    $key_1a5a = { 49 35 [2] 6d 3b [2] 46 17 [2] 68 35 [2] 7c 2e [2] 73 34 [2] 6d 29 [2] 6f 28 [2] 74 2e [2] 68 29 [2] 74 06 }

  condition:
    any of them
}