rule TTP_XOR_QUAD_CurrentVersionRun_0171 {
  strings:
    $key_0171 = { 52 1e [2] 76 10 [2] 5d 3c [2] 73 1e [2] 67 05 [2] 68 1f [2] 76 02 [2] 74 03 [2] 6f 05 [2] 73 02 [2] 6f 2d }

  condition:
    any of them
}