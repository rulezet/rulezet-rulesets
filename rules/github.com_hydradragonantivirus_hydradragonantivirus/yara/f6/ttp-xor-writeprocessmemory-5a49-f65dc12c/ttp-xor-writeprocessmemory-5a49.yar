rule TTP_XOR_WriteProcessMemory_5a49 {
  strings:
    $key_5a49 = { 0d 3b [2] 3f 19 [2] 39 2c [2] 17 2c [2] 28 30 }

  condition:
    any of them
}