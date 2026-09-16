rule TTP_XOR_WriteProcessMemory_10e2 {
  strings:
    $key_10e2 = { 47 90 [2] 75 b2 [2] 73 87 [2] 5d 87 [2] 62 9b }

  condition:
    any of them
}