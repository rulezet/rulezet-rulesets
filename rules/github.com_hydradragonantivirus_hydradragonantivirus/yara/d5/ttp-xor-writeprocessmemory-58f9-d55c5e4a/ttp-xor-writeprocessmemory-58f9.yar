rule TTP_XOR_WriteProcessMemory_58f9 {
  strings:
    $key_58f9 = { 0f 8b [2] 3d a9 [2] 3b 9c [2] 15 9c [2] 2a 80 }

  condition:
    any of them
}