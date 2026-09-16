rule TTP_XOR_QUAD_CurrentVersionRun_1c1a {
  strings:
    $key_1c1a = { 4f 75 [2] 6b 7b [2] 40 57 [2] 6e 75 [2] 7a 6e [2] 75 74 [2] 6b 69 [2] 69 68 [2] 72 6e [2] 6e 69 [2] 72 46 }

  condition:
    any of them
}