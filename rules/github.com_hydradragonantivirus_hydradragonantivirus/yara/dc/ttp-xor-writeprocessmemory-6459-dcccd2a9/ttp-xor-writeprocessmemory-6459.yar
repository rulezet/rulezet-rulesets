rule TTP_XOR_WriteProcessMemory_6459 {
  strings:
    $key_6459 = { 33 2b [2] 01 09 [2] 07 3c [2] 29 3c [2] 16 20 }

  condition:
    any of them
}