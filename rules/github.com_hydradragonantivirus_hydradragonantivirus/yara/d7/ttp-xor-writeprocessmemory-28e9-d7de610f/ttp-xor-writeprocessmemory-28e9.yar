rule TTP_XOR_WriteProcessMemory_28e9 {
  strings:
    $key_28e9 = { 7f 9b [2] 4d b9 [2] 4b 8c [2] 65 8c [2] 5a 90 }

  condition:
    any of them
}