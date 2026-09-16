rule TTP_XOR_WriteProcessMemory_5570 {
  strings:
    $key_5570 = { 02 02 [2] 30 20 [2] 36 15 [2] 18 15 [2] 27 09 }

  condition:
    any of them
}