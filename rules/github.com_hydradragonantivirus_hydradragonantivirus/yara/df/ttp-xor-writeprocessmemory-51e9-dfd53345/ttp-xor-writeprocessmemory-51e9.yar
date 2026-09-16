rule TTP_XOR_WriteProcessMemory_51e9 {
  strings:
    $key_51e9 = { 06 9b [2] 34 b9 [2] 32 8c [2] 1c 8c [2] 23 90 }

  condition:
    any of them
}