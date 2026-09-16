rule TTP_XOR_WriteProcessMemory_90e9 {
  strings:
    $key_90e9 = { c7 9b [2] f5 b9 [2] f3 8c [2] dd 8c [2] e2 90 }

  condition:
    any of them
}