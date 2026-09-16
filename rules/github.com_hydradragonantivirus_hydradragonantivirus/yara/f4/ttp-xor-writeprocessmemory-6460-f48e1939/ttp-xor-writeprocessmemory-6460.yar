rule TTP_XOR_WriteProcessMemory_6460 {
  strings:
    $key_6460 = { 33 12 [2] 01 30 [2] 07 05 [2] 29 05 [2] 16 19 }

  condition:
    any of them
}