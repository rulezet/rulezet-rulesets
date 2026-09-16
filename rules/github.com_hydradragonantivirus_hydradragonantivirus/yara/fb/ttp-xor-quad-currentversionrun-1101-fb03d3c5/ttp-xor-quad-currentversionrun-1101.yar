rule TTP_XOR_QUAD_CurrentVersionRun_1101 {
  strings:
    $key_1101 = { 42 6e [2] 66 60 [2] 4d 4c [2] 63 6e [2] 77 75 [2] 78 6f [2] 66 72 [2] 64 73 [2] 7f 75 [2] 63 72 [2] 7f 5d }

  condition:
    any of them
}