rule TTP_XOR_WriteProcessMemory_7129 {
  strings:
    $key_7129 = { 26 5b [2] 14 79 [2] 12 4c [2] 3c 4c [2] 03 50 }

  condition:
    any of them
}