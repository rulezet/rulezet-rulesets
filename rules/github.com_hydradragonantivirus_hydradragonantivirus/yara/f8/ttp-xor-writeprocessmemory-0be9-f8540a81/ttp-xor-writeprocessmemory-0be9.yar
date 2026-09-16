rule TTP_XOR_WriteProcessMemory_0be9 {
  strings:
    $key_0be9 = { 5c 9b [2] 6e b9 [2] 68 8c [2] 46 8c [2] 79 90 }

  condition:
    any of them
}