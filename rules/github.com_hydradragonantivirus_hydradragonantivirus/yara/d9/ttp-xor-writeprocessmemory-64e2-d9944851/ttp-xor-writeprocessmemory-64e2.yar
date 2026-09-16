rule TTP_XOR_WriteProcessMemory_64e2 {
  strings:
    $key_64e2 = { 33 90 [2] 01 b2 [2] 07 87 [2] 29 87 [2] 16 9b }

  condition:
    any of them
}