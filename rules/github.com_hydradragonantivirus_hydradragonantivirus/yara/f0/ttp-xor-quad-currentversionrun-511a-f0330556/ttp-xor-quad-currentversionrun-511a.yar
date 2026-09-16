rule TTP_XOR_QUAD_CurrentVersionRun_511a {
  strings:
    $key_511a = { 02 75 [2] 26 7b [2] 0d 57 [2] 23 75 [2] 37 6e [2] 38 74 [2] 26 69 [2] 24 68 [2] 3f 6e [2] 23 69 [2] 3f 46 }

  condition:
    any of them
}