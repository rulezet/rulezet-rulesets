rule TTP_XOR_WriteProcessMemory_27e7 {
  strings:
    $key_27e7 = { 70 95 [2] 42 b7 [2] 44 82 [2] 6a 82 [2] 55 9e }

  condition:
    any of them
}