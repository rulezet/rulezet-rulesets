rule TTP_XOR_WriteProcessMemory_f359 {
  strings:
    $key_f359 = { a4 2b [2] 96 09 [2] 90 3c [2] be 3c [2] 81 20 }

  condition:
    any of them
}