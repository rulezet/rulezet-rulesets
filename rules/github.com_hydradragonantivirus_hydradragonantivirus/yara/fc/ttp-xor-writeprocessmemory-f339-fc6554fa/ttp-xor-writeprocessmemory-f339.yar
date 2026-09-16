rule TTP_XOR_WriteProcessMemory_f339 {
  strings:
    $key_f339 = { a4 4b [2] 96 69 [2] 90 5c [2] be 5c [2] 81 40 }

  condition:
    any of them
}