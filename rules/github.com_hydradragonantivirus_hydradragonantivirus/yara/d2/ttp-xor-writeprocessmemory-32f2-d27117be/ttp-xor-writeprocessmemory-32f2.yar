rule TTP_XOR_WriteProcessMemory_32f2 {
  strings:
    $key_32f2 = { 65 80 [2] 57 a2 [2] 51 97 [2] 7f 97 [2] 40 8b }

  condition:
    any of them
}