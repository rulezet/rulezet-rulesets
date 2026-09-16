rule TTP_XOR_QUAD_CurrentVersionRun_7b26 {
  strings:
    $key_7b26 = { 28 49 [2] 0c 47 [2] 27 6b [2] 09 49 [2] 1d 52 [2] 12 48 [2] 0c 55 [2] 0e 54 [2] 15 52 [2] 09 55 [2] 15 7a }

  condition:
    any of them
}