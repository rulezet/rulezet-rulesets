rule TTP_XOR_WriteProcessMemory_1579 {
  strings:
    $key_1579 = { 42 0b [2] 70 29 [2] 76 1c [2] 58 1c [2] 67 00 }

  condition:
    any of them
}