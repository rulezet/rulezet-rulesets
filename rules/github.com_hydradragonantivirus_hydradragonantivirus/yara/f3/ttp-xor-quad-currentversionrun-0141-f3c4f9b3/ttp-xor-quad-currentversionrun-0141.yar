rule TTP_XOR_QUAD_CurrentVersionRun_0141 {
  strings:
    $key_0141 = { 52 2e [2] 76 20 [2] 5d 0c [2] 73 2e [2] 67 35 [2] 68 2f [2] 76 32 [2] 74 33 [2] 6f 35 [2] 73 32 [2] 6f 1d }

  condition:
    any of them
}