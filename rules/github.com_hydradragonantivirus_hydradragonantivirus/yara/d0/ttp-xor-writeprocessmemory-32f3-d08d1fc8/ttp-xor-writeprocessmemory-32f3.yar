rule TTP_XOR_WriteProcessMemory_32f3 {
  strings:
    $key_32f3 = { 65 81 [2] 57 a3 [2] 51 96 [2] 7f 96 [2] 40 8a }

  condition:
    any of them
}