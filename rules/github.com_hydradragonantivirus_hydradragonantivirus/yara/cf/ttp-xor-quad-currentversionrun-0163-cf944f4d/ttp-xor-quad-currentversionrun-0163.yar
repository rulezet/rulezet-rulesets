rule TTP_XOR_QUAD_CurrentVersionRun_0163 {
  strings:
    $key_0163 = { 52 0c [2] 76 02 [2] 5d 2e [2] 73 0c [2] 67 17 [2] 68 0d [2] 76 10 [2] 74 11 [2] 6f 17 [2] 73 10 [2] 6f 3f }

  condition:
    any of them
}