rule TTP_XOR_WriteProcessMemory_5909 {
  strings:
    $key_5909 = { 0e 7b [2] 3c 59 [2] 3a 6c [2] 14 6c [2] 2b 70 }

  condition:
    any of them
}