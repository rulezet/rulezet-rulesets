rule TTP_XOR_WriteProcessMemory_5436 {
  strings:
    $key_5436 = { 03 44 [2] 31 66 [2] 37 53 [2] 19 53 [2] 26 4f }

  condition:
    any of them
}