rule TTP_XOR_WriteProcessMemory_0af9 {
  strings:
    $key_0af9 = { 5d 8b [2] 6f a9 [2] 69 9c [2] 47 9c [2] 78 80 }

  condition:
    any of them
}