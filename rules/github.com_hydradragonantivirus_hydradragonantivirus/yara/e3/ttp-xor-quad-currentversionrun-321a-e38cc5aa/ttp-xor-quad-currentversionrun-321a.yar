rule TTP_XOR_QUAD_CurrentVersionRun_321a {
  strings:
    $key_321a = { 61 75 [2] 45 7b [2] 6e 57 [2] 40 75 [2] 54 6e [2] 5b 74 [2] 45 69 [2] 47 68 [2] 5c 6e [2] 40 69 [2] 5c 46 }

  condition:
    any of them
}