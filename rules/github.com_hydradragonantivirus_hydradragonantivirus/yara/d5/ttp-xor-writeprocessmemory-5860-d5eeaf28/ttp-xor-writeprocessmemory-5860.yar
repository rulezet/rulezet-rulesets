rule TTP_XOR_WriteProcessMemory_5860 {
  strings:
    $key_5860 = { 0f 12 [2] 3d 30 [2] 3b 05 [2] 15 05 [2] 2a 19 }

  condition:
    any of them
}