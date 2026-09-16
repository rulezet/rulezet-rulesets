rule TTP_XOR_WriteProcessMemory_32f0 {
  strings:
    $key_32f0 = { 65 82 [2] 57 a0 [2] 51 95 [2] 7f 95 [2] 40 89 }

  condition:
    any of them
}