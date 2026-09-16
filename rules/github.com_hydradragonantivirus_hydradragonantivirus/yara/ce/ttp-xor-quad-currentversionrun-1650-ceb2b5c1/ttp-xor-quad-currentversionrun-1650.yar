rule TTP_XOR_QUAD_CurrentVersionRun_1650 {
  strings:
    $key_1650 = { 45 3f [2] 61 31 [2] 4a 1d [2] 64 3f [2] 70 24 [2] 7f 3e [2] 61 23 [2] 63 22 [2] 78 24 [2] 64 23 [2] 78 0c }

  condition:
    any of them
}