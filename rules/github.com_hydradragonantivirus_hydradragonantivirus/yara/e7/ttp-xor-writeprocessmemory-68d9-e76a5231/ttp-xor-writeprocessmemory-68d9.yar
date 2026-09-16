rule TTP_XOR_WriteProcessMemory_68d9 {
  strings:
    $key_68d9 = { 3f ab [2] 0d 89 [2] 0b bc [2] 25 bc [2] 1a a0 }

  condition:
    any of them
}