rule TTP_XOR_WriteProcessMemory_1419 {
  strings:
    $key_1419 = { 43 6b [2] 71 49 [2] 77 7c [2] 59 7c [2] 66 60 }

  condition:
    any of them
}