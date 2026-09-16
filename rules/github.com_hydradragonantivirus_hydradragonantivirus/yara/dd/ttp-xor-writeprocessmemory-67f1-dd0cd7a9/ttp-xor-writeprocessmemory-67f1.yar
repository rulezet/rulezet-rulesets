rule TTP_XOR_WriteProcessMemory_67f1 {
  strings:
    $key_67f1 = { 30 83 [2] 02 a1 [2] 04 94 [2] 2a 94 [2] 15 88 }

  condition:
    any of them
}