rule TTP_XOR_QUAD_CurrentVersionRun_252a {
  strings:
    $key_252a = { 76 45 [2] 52 4b [2] 79 67 [2] 57 45 [2] 43 5e [2] 4c 44 [2] 52 59 [2] 50 58 [2] 4b 5e [2] 57 59 [2] 4b 76 }

  condition:
    any of them
}