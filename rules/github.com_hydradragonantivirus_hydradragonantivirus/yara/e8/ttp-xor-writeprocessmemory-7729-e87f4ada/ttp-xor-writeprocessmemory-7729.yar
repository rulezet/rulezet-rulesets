rule TTP_XOR_WriteProcessMemory_7729 {
  strings:
    $key_7729 = { 20 5b [2] 12 79 [2] 14 4c [2] 3a 4c [2] 05 50 }

  condition:
    any of them
}