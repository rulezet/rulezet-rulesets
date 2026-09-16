rule TTP_XOR_QUAD_CurrentVersionRun_5651 {
  strings:
    $key_5651 = { 05 3e [2] 21 30 [2] 0a 1c [2] 24 3e [2] 30 25 [2] 3f 3f [2] 21 22 [2] 23 23 [2] 38 25 [2] 24 22 [2] 38 0d }

  condition:
    any of them
}