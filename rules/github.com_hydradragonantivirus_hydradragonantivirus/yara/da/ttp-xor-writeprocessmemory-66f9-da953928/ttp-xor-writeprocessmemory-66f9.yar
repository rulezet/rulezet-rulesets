rule TTP_XOR_WriteProcessMemory_66f9 {
  strings:
    $key_66f9 = { 31 8b [2] 03 a9 [2] 05 9c [2] 2b 9c [2] 14 80 }

  condition:
    any of them
}