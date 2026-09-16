rule TTP_XOR_QUAD_CurrentVersionRun_7b2d {
  strings:
    $key_7b2d = { 28 42 [2] 0c 4c [2] 27 60 [2] 09 42 [2] 1d 59 [2] 12 43 [2] 0c 5e [2] 0e 5f [2] 15 59 [2] 09 5e [2] 15 71 }

  condition:
    any of them
}