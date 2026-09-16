rule TTP_XOR_WriteProcessMemory_7849 {
  strings:
    $key_7849 = { 2f 3b [2] 1d 19 [2] 1b 2c [2] 35 2c [2] 0a 30 }

  condition:
    any of them
}