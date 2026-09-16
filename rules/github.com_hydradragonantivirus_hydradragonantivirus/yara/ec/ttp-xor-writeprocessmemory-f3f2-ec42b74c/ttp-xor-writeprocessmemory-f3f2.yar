rule TTP_XOR_WriteProcessMemory_f3f2 {
  strings:
    $key_f3f2 = { a4 80 [2] 96 a2 [2] 90 97 [2] be 97 [2] 81 8b }

  condition:
    any of them
}