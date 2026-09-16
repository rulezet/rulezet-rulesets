rule TTP_XOR_WriteProcessMemory_0a49 {
  strings:
    $key_0a49 = { 5d 3b [2] 6f 19 [2] 69 2c [2] 47 2c [2] 78 30 }

  condition:
    any of them
}