rule TTP_XOR_QUAD_CurrentVersionRun_567d {
  strings:
    $key_567d = { 05 12 [2] 21 1c [2] 0a 30 [2] 24 12 [2] 30 09 [2] 3f 13 [2] 21 0e [2] 23 0f [2] 38 09 [2] 24 0e [2] 38 21 }

  condition:
    any of them
}