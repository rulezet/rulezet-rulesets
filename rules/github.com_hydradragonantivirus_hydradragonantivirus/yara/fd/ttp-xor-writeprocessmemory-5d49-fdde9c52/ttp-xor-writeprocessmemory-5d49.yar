rule TTP_XOR_WriteProcessMemory_5d49 {
  strings:
    $key_5d49 = { 0a 3b [2] 38 19 [2] 3e 2c [2] 10 2c [2] 2f 30 }

  condition:
    any of them
}