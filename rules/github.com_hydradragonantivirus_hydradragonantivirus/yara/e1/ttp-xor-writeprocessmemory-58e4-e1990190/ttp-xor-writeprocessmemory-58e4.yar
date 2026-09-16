rule TTP_XOR_WriteProcessMemory_58e4 {
  strings:
    $key_58e4 = { 0f 96 [2] 3d b4 [2] 3b 81 [2] 15 81 [2] 2a 9d }

  condition:
    any of them
}