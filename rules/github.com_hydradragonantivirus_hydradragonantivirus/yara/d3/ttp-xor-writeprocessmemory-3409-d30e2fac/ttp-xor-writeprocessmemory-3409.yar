rule TTP_XOR_WriteProcessMemory_3409 {
  strings:
    $key_3409 = { 63 7b [2] 51 59 [2] 57 6c [2] 79 6c [2] 46 70 }

  condition:
    any of them
}