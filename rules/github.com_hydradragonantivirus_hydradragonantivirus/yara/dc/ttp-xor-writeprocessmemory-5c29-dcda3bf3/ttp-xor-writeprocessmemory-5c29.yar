rule TTP_XOR_WriteProcessMemory_5c29 {
  strings:
    $key_5c29 = { 0b 5b [2] 39 79 [2] 3f 4c [2] 11 4c [2] 2e 50 }

  condition:
    any of them
}