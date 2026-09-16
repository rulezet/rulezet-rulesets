rule TTP_XOR_WriteProcessMemory_1501 {
  strings:
    $key_1501 = { 42 73 [2] 70 51 [2] 76 64 [2] 58 64 [2] 67 78 }

  condition:
    any of them
}