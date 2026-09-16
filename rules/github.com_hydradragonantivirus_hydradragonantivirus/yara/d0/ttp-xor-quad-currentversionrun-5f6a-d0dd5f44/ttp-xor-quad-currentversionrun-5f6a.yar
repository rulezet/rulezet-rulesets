rule TTP_XOR_QUAD_CurrentVersionRun_5f6a {
  strings:
    $key_5f6a = { 0c 05 [2] 28 0b [2] 03 27 [2] 2d 05 [2] 39 1e [2] 36 04 [2] 28 19 [2] 2a 18 [2] 31 1e [2] 2d 19 [2] 31 36 }

  condition:
    any of them
}