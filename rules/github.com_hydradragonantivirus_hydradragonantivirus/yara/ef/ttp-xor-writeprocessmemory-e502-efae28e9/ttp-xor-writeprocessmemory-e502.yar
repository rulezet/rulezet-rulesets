rule TTP_XOR_WriteProcessMemory_e502 {
  strings:
    $key_e502 = { b2 70 [2] 80 52 [2] 86 67 [2] a8 67 [2] 97 7b }

  condition:
    any of them
}