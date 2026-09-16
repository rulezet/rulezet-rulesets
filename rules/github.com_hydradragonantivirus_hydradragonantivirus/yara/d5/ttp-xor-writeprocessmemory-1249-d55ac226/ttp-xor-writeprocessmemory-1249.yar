rule TTP_XOR_WriteProcessMemory_1249 {
  strings:
    $key_1249 = { 45 3b [2] 77 19 [2] 71 2c [2] 5f 2c [2] 60 30 }

  condition:
    any of them
}