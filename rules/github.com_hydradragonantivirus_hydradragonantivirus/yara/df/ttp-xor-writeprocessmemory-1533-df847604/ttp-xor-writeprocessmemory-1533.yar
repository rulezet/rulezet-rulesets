rule TTP_XOR_WriteProcessMemory_1533 {
  strings:
    $key_1533 = { 42 41 [2] 70 63 [2] 76 56 [2] 58 56 [2] 67 4a }

  condition:
    any of them
}