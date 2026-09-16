rule TTP_XOR_WriteProcessMemory_58e7 {
  strings:
    $key_58e7 = { 0f 95 [2] 3d b7 [2] 3b 82 [2] 15 82 [2] 2a 9e }

  condition:
    any of them
}