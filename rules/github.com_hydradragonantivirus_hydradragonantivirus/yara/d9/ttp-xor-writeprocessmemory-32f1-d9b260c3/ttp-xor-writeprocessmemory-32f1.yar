rule TTP_XOR_WriteProcessMemory_32f1 {
  strings:
    $key_32f1 = { 65 83 [2] 57 a1 [2] 51 94 [2] 7f 94 [2] 40 88 }

  condition:
    any of them
}