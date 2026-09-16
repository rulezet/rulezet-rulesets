rule TTP_XOR_WriteProcessMemory_0b09 {
  strings:
    $key_0b09 = { 5c 7b [2] 6e 59 [2] 68 6c [2] 46 6c [2] 79 70 }

  condition:
    any of them
}