rule TTP_XOR_WriteProcessMemory_3200 {
  strings:
    $key_3200 = { 65 72 [2] 57 50 [2] 51 65 [2] 7f 65 [2] 40 79 }

  condition:
    any of them
}