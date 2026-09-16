rule TTP_XOR_QUAD_CurrentVersionRun_1a50 {
  strings:
    $key_1a50 = { 49 3f [2] 6d 31 [2] 46 1d [2] 68 3f [2] 7c 24 [2] 73 3e [2] 6d 23 [2] 6f 22 [2] 74 24 [2] 68 23 [2] 74 0c }

  condition:
    any of them
}