rule TTP_XOR_WriteProcessMemory_6066 {
  strings:
    $key_6066 = { 37 14 [2] 05 36 [2] 03 03 [2] 2d 03 [2] 12 1f }

  condition:
    any of them
}