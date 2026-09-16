rule TTP_XOR_WriteProcessMemory_4149 {
  strings:
    $key_4149 = { 16 3b [2] 24 19 [2] 22 2c [2] 0c 2c [2] 33 30 }

  condition:
    any of them
}