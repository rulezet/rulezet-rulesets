rule TTP_XOR_WriteProcessMemory_5be9 {
  strings:
    $key_5be9 = { 0c 9b [2] 3e b9 [2] 38 8c [2] 16 8c [2] 29 90 }

  condition:
    any of them
}