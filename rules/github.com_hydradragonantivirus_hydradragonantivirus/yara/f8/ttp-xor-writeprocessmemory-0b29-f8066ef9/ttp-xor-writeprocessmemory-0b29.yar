rule TTP_XOR_WriteProcessMemory_0b29 {
  strings:
    $key_0b29 = { 5c 5b [2] 6e 79 [2] 68 4c [2] 46 4c [2] 79 50 }

  condition:
    any of them
}