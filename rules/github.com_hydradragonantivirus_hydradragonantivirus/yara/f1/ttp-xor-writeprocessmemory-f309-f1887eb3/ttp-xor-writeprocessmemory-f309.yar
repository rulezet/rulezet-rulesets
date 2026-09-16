rule TTP_XOR_WriteProcessMemory_f309 {
  strings:
    $key_f309 = { a4 7b [2] 96 59 [2] 90 6c [2] be 6c [2] 81 70 }

  condition:
    any of them
}