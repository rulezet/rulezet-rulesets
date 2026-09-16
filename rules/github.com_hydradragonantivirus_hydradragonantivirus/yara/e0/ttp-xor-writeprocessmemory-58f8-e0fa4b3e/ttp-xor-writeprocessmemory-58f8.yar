rule TTP_XOR_WriteProcessMemory_58f8 {
  strings:
    $key_58f8 = { 0f 8a [2] 3d a8 [2] 3b 9d [2] 15 9d [2] 2a 81 }

  condition:
    any of them
}