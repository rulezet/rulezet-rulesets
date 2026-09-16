rule TTP_XOR_WriteProcessMemory_1409 {
  strings:
    $key_1409 = { 43 7b [2] 71 59 [2] 77 6c [2] 59 6c [2] 66 70 }

  condition:
    any of them
}