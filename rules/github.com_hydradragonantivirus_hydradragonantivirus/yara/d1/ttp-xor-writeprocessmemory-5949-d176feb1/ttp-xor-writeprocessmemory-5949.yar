rule TTP_XOR_WriteProcessMemory_5949 {
  strings:
    $key_5949 = { 0e 3b [2] 3c 19 [2] 3a 2c [2] 14 2c [2] 2b 30 }

  condition:
    any of them
}