rule TTP_XOR_WriteProcessMemory_58f3 {
  strings:
    $key_58f3 = { 0f 81 [2] 3d a3 [2] 3b 96 [2] 15 96 [2] 2a 8a }

  condition:
    any of them
}