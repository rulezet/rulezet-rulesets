rule TTP_XOR_WriteProcessMemory_6002 {
  strings:
    $key_6002 = { 37 70 [2] 05 52 [2] 03 67 [2] 2d 67 [2] 12 7b }

  condition:
    any of them
}