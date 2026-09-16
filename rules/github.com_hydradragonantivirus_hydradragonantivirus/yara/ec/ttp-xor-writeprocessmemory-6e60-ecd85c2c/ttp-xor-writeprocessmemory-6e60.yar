rule TTP_XOR_WriteProcessMemory_6e60 {
  strings:
    $key_6e60 = { 39 12 [2] 0b 30 [2] 0d 05 [2] 23 05 [2] 1c 19 }

  condition:
    any of them
}