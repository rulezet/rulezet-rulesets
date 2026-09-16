rule TTP_XOR_WriteProcessMemory_2349 {
  strings:
    $key_2349 = { 74 3b [2] 46 19 [2] 40 2c [2] 6e 2c [2] 51 30 }

  condition:
    any of them
}