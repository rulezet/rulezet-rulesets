rule TTP_XOR_QUAD_CurrentVersionRun_501a {
  strings:
    $key_501a = { 03 75 [2] 27 7b [2] 0c 57 [2] 22 75 [2] 36 6e [2] 39 74 [2] 27 69 [2] 25 68 [2] 3e 6e [2] 22 69 [2] 3e 46 }

  condition:
    any of them
}