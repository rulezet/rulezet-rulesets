rule TTP_XOR_QUAD_CurrentVersionRun_6471 {
  strings:
    $key_6471 = { 37 1e [2] 13 10 [2] 38 3c [2] 16 1e [2] 02 05 [2] 0d 1f [2] 13 02 [2] 11 03 [2] 0a 05 [2] 16 02 [2] 0a 2d }

  condition:
    any of them
}