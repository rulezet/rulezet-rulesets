rule TTP_XOR_QUAD_CurrentVersionRun_7b33 {
  strings:
    $key_7b33 = { 28 5c [2] 0c 52 [2] 27 7e [2] 09 5c [2] 1d 47 [2] 12 5d [2] 0c 40 [2] 0e 41 [2] 15 47 [2] 09 40 [2] 15 6f }

  condition:
    any of them
}