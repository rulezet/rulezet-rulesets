rule TTP_XOR_WriteProcessMemory_1429 {
  strings:
    $key_1429 = { 43 5b [2] 71 79 [2] 77 4c [2] 59 4c [2] 66 50 }

  condition:
    any of them
}