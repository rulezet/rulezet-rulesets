rule TTP_XOR_WriteProcessMemory_6e49 {
  strings:
    $key_6e49 = { 39 3b [2] 0b 19 [2] 0d 2c [2] 23 2c [2] 1c 30 }

  condition:
    any of them
}