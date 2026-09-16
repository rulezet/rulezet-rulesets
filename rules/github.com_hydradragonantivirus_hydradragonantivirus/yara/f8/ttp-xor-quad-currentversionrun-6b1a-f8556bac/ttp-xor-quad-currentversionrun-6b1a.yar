rule TTP_XOR_QUAD_CurrentVersionRun_6b1a {
  strings:
    $key_6b1a = { 38 75 [2] 1c 7b [2] 37 57 [2] 19 75 [2] 0d 6e [2] 02 74 [2] 1c 69 [2] 1e 68 [2] 05 6e [2] 19 69 [2] 05 46 }

  condition:
    any of them
}