rule TTP_XOR_WriteProcessMemory_1170 {
  strings:
    $key_1170 = { 46 02 [2] 74 20 [2] 72 15 [2] 5c 15 [2] 63 09 }

  condition:
    any of them
}