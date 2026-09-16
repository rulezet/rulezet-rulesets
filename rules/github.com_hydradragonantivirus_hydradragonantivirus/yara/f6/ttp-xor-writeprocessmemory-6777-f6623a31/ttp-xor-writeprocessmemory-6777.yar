rule TTP_XOR_WriteProcessMemory_6777 {
  strings:
    $key_6777 = { 30 05 [2] 02 27 [2] 04 12 [2] 2a 12 [2] 15 0e }

  condition:
    any of them
}