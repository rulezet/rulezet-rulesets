rule TTP_XOR_WriteProcessMemory_6760 {
  strings:
    $key_6760 = { 30 12 [2] 02 30 [2] 04 05 [2] 2a 05 [2] 15 19 }

  condition:
    any of them
}