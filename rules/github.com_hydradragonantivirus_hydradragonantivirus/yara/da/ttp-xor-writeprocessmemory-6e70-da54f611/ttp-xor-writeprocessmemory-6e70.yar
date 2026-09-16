rule TTP_XOR_WriteProcessMemory_6e70 {
  strings:
    $key_6e70 = { 39 02 [2] 0b 20 [2] 0d 15 [2] 23 15 [2] 1c 09 }

  condition:
    any of them
}