rule TTP_XOR_WriteProcessMemory_3a29 {
  strings:
    $key_3a29 = { 6d 5b [2] 5f 79 [2] 59 4c [2] 77 4c [2] 48 50 }

  condition:
    any of them
}