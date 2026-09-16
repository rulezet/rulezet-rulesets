rule TTP_XOR_QUAD_CurrentVersionRun_1801 {
  strings:
    $key_1801 = { 4b 6e [2] 6f 60 [2] 44 4c [2] 6a 6e [2] 7e 75 [2] 71 6f [2] 6f 72 [2] 6d 73 [2] 76 75 [2] 6a 72 [2] 76 5d }

  condition:
    any of them
}