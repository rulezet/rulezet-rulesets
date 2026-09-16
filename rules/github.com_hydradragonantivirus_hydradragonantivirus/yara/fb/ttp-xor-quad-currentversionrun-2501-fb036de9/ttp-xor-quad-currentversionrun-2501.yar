rule TTP_XOR_QUAD_CurrentVersionRun_2501 {
  strings:
    $key_2501 = { 76 6e [2] 52 60 [2] 79 4c [2] 57 6e [2] 43 75 [2] 4c 6f [2] 52 72 [2] 50 73 [2] 4b 75 [2] 57 72 [2] 4b 5d }

  condition:
    any of them
}