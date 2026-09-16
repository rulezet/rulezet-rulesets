rule TTP_XOR_WriteProcessMemory_6f66 {
  strings:
    $key_6f66 = { 38 14 [2] 0a 36 [2] 0c 03 [2] 22 03 [2] 1d 1f }

  condition:
    any of them
}