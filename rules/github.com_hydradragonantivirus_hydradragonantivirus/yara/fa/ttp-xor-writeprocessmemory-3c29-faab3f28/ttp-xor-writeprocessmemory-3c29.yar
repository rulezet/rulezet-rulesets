rule TTP_XOR_WriteProcessMemory_3c29 {
  strings:
    $key_3c29 = { 6b 5b [2] 59 79 [2] 5f 4c [2] 71 4c [2] 4e 50 }

  condition:
    any of them
}