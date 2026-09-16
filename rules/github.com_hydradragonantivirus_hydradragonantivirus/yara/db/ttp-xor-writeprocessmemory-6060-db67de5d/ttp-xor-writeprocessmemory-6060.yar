rule TTP_XOR_WriteProcessMemory_6060 {
  strings:
    $key_6060 = { 37 12 [2] 05 30 [2] 03 05 [2] 2d 05 [2] 12 19 }

  condition:
    any of them
}