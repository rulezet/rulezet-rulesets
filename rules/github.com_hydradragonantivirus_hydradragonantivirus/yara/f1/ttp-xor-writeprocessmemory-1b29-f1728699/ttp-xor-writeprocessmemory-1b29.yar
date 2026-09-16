rule TTP_XOR_WriteProcessMemory_1b29 {
  strings:
    $key_1b29 = { 4c 5b [2] 7e 79 [2] 78 4c [2] 56 4c [2] 69 50 }

  condition:
    any of them
}