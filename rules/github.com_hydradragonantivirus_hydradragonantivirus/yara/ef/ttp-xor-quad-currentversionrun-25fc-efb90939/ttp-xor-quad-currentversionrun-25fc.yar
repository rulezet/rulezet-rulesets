rule TTP_XOR_QUAD_CurrentVersionRun_25fc {
  strings:
    $key_25fc = { 76 93 [2] 52 9d [2] 79 b1 [2] 57 93 [2] 43 88 [2] 4c 92 [2] 52 8f [2] 50 8e [2] 4b 88 [2] 57 8f [2] 4b a0 }

  condition:
    any of them
}