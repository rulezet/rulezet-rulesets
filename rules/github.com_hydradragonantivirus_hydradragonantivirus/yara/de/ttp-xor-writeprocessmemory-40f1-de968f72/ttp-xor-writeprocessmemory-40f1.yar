rule TTP_XOR_WriteProcessMemory_40f1 {
  strings:
    $key_40f1 = { 17 83 [2] 25 a1 [2] 23 94 [2] 0d 94 [2] 32 88 }

  condition:
    any of them
}