rule TTP_XOR_QUAD_CurrentVersionRun_445a {
  strings:
    $key_445a = { 17 35 [2] 33 3b [2] 18 17 [2] 36 35 [2] 22 2e [2] 2d 34 [2] 33 29 [2] 31 28 [2] 2a 2e [2] 36 29 [2] 2a 06 }

  condition:
    any of them
}