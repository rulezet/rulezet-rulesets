rule TTP_XOR_WriteProcessMemory_1929 {
  strings:
    $key_1929 = { 4e 5b [2] 7c 79 [2] 7a 4c [2] 54 4c [2] 6b 50 }

  condition:
    any of them
}