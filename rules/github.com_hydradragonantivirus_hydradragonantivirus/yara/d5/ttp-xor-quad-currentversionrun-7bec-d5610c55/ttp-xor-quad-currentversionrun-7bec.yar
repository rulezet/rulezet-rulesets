rule TTP_XOR_QUAD_CurrentVersionRun_7bec {
  strings:
    $key_7bec = { 28 83 [2] 0c 8d [2] 27 a1 [2] 09 83 [2] 1d 98 [2] 12 82 [2] 0c 9f [2] 0e 9e [2] 15 98 [2] 09 9f [2] 15 b0 }

  condition:
    any of them
}