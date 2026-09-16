rule TTP_XOR_WriteProcessMemory_1514 {
  strings:
    $key_1514 = { 42 66 [2] 70 44 [2] 76 71 [2] 58 71 [2] 67 6d }

  condition:
    any of them
}