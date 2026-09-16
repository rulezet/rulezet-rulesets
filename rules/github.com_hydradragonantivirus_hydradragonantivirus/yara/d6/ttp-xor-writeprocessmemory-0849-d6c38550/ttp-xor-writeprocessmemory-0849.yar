rule TTP_XOR_WriteProcessMemory_0849 {
  strings:
    $key_0849 = { 5f 3b [2] 6d 19 [2] 6b 2c [2] 45 2c [2] 7a 30 }

  condition:
    any of them
}