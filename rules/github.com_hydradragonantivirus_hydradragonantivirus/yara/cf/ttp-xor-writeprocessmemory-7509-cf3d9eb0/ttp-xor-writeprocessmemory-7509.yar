rule TTP_XOR_WriteProcessMemory_7509 {
  strings:
    $key_7509 = { 22 7b [2] 10 59 [2] 16 6c [2] 38 6c [2] 07 70 }

  condition:
    any of them
}