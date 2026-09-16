rule TTP_XOR_QUAD_CurrentVersionRun_554a {
  strings:
    $key_554a = { 06 25 [2] 22 2b [2] 09 07 [2] 27 25 [2] 33 3e [2] 3c 24 [2] 22 39 [2] 20 38 [2] 3b 3e [2] 27 39 [2] 3b 16 }

  condition:
    any of them
}