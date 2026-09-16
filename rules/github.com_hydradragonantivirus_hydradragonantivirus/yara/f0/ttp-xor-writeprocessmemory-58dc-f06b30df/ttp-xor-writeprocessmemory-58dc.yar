rule TTP_XOR_WriteProcessMemory_58dc {
  strings:
    $key_58dc = { 0f ae [2] 3d 8c [2] 3b b9 [2] 15 b9 [2] 2a a5 }

  condition:
    any of them
}