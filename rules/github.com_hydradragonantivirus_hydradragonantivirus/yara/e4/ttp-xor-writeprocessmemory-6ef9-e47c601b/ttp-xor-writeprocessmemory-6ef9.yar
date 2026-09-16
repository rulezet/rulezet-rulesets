rule TTP_XOR_WriteProcessMemory_6ef9 {
  strings:
    $key_6ef9 = { 39 8b [2] 0b a9 [2] 0d 9c [2] 23 9c [2] 1c 80 }

  condition:
    any of them
}