rule TTP_XOR_WriteProcessMemory_41e9 {
  strings:
    $key_41e9 = { 16 9b [2] 24 b9 [2] 22 8c [2] 0c 8c [2] 33 90 }

  condition:
    any of them
}