rule TTP_XOR_QUAD_CurrentVersionRun_683a {
  strings:
    $key_683a = { 3b 55 [2] 1f 5b [2] 34 77 [2] 1a 55 [2] 0e 4e [2] 01 54 [2] 1f 49 [2] 1d 48 [2] 06 4e [2] 1a 49 [2] 06 66 }

  condition:
    any of them
}