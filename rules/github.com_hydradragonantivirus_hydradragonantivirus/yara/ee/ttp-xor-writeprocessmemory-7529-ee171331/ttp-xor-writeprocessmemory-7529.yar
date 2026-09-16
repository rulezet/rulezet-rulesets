rule TTP_XOR_WriteProcessMemory_7529 {
  strings:
    $key_7529 = { 22 5b [2] 10 79 [2] 16 4c [2] 38 4c [2] 07 50 }

  condition:
    any of them
}