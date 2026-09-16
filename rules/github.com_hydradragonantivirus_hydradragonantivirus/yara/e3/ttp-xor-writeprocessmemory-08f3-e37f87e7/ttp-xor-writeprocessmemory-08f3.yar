rule TTP_XOR_WriteProcessMemory_08f3 {
  strings:
    $key_08f3 = { 5f 81 [2] 6d a3 [2] 6b 96 [2] 45 96 [2] 7a 8a }

  condition:
    any of them
}