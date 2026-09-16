rule TTP_XOR_QUAD_CurrentVersionRun_601a {
  strings:
    $key_601a = { 33 75 [2] 17 7b [2] 3c 57 [2] 12 75 [2] 06 6e [2] 09 74 [2] 17 69 [2] 15 68 [2] 0e 6e [2] 12 69 [2] 0e 46 }

  condition:
    any of them
}