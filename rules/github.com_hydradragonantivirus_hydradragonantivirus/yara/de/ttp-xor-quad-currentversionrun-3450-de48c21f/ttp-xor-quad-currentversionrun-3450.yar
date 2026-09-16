rule TTP_XOR_QUAD_CurrentVersionRun_3450 {
  strings:
    $key_3450 = { 67 3f [2] 43 31 [2] 68 1d [2] 46 3f [2] 52 24 [2] 5d 3e [2] 43 23 [2] 41 22 [2] 5a 24 [2] 46 23 [2] 5a 0c }

  condition:
    any of them
}