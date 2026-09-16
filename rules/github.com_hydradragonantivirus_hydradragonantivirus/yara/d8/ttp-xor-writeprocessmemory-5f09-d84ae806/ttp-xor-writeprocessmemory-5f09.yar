rule TTP_XOR_WriteProcessMemory_5f09 {
  strings:
    $key_5f09 = { 08 7b [2] 3a 59 [2] 3c 6c [2] 12 6c [2] 2d 70 }

  condition:
    any of them
}