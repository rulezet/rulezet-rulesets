rule TTP_XOR_WriteProcessMemory_4435 {
  strings:
    $key_4435 = { 13 47 [2] 21 65 [2] 27 50 [2] 09 50 [2] 36 4c }

  condition:
    any of them
}