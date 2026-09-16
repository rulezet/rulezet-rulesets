rule TTP_XOR_WriteProcessMemory_4e49 {
  strings:
    $key_4e49 = { 19 3b [2] 2b 19 [2] 2d 2c [2] 03 2c [2] 3c 30 }

  condition:
    any of them
}