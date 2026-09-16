rule TTP_XOR_WriteProcessMemory_40e9 {
  strings:
    $key_40e9 = { 17 9b [2] 25 b9 [2] 23 8c [2] 0d 8c [2] 32 90 }

  condition:
    any of them
}