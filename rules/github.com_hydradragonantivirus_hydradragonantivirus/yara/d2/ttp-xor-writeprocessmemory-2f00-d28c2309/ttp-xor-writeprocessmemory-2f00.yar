rule TTP_XOR_WriteProcessMemory_2f00 {
  strings:
    $key_2f00 = { 78 72 [2] 4a 50 [2] 4c 65 [2] 62 65 [2] 5d 79 }

  condition:
    any of them
}