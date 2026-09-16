rule TTP_XOR_QUAD_CurrentVersionRun_6b7d {
  strings:
    $key_6b7d = { 38 12 [2] 1c 1c [2] 37 30 [2] 19 12 [2] 0d 09 [2] 02 13 [2] 1c 0e [2] 1e 0f [2] 05 09 [2] 19 0e [2] 05 21 }

  condition:
    any of them
}