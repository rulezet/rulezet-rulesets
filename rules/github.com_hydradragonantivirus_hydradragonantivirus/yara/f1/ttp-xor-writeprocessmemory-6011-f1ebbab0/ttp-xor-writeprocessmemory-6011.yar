rule TTP_XOR_WriteProcessMemory_6011 {
  strings:
    $key_6011 = { 37 63 [2] 05 41 [2] 03 74 [2] 2d 74 [2] 12 68 }

  condition:
    any of them
}