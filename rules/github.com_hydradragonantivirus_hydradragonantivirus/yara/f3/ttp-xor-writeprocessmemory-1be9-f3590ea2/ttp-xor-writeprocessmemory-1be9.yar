rule TTP_XOR_WriteProcessMemory_1be9 {
  strings:
    $key_1be9 = { 4c 9b [2] 7e b9 [2] 78 8c [2] 56 8c [2] 69 90 }

  condition:
    any of them
}