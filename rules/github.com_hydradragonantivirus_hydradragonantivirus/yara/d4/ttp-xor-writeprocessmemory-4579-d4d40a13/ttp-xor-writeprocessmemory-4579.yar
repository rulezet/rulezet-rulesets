rule TTP_XOR_WriteProcessMemory_4579 {
  strings:
    $key_4579 = { 12 0b [2] 20 29 [2] 26 1c [2] 08 1c [2] 37 00 }

  condition:
    any of them
}