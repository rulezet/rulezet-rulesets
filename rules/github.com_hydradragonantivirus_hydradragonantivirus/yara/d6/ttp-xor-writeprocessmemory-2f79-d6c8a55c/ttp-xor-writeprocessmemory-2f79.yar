rule TTP_XOR_WriteProcessMemory_2f79 {
  strings:
    $key_2f79 = { 78 0b [2] 4a 29 [2] 4c 1c [2] 62 1c [2] 5d 00 }

  condition:
    any of them
}