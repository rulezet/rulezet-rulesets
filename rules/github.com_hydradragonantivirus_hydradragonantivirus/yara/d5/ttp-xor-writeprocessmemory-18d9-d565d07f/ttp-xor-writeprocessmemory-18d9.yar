rule TTP_XOR_WriteProcessMemory_18d9 {
  strings:
    $key_18d9 = { 4f ab [2] 7d 89 [2] 7b bc [2] 55 bc [2] 6a a0 }

  condition:
    any of them
}