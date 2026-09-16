rule TTP_XOR_QUAD_CurrentVersionRun_0101 {
  strings:
    $key_0101 = { 52 6e [2] 76 60 [2] 5d 4c [2] 73 6e [2] 67 75 [2] 68 6f [2] 76 72 [2] 74 73 [2] 6f 75 [2] 73 72 [2] 6f 5d }

  condition:
    any of them
}