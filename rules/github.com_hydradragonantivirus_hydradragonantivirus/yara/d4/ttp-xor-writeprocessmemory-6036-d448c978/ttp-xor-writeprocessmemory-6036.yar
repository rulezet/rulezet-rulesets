rule TTP_XOR_WriteProcessMemory_6036 {
  strings:
    $key_6036 = { 37 44 [2] 05 66 [2] 03 53 [2] 2d 53 [2] 12 4f }

  condition:
    any of them
}