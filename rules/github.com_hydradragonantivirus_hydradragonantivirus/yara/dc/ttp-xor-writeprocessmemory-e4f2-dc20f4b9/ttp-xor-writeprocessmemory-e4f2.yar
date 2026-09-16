rule TTP_XOR_WriteProcessMemory_e4f2 {
  strings:
    $key_e4f2 = { b3 80 [2] 81 a2 [2] 87 97 [2] a9 97 [2] 96 8b }

  condition:
    any of them
}