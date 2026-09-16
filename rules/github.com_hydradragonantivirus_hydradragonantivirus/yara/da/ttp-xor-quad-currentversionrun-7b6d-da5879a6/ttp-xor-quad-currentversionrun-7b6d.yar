rule TTP_XOR_QUAD_CurrentVersionRun_7b6d {
  strings:
    $key_7b6d = { 28 02 [2] 0c 0c [2] 27 20 [2] 09 02 [2] 1d 19 [2] 12 03 [2] 0c 1e [2] 0e 1f [2] 15 19 [2] 09 1e [2] 15 31 }

  condition:
    any of them
}