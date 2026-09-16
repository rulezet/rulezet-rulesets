rule TTP_XOR_WriteProcessMemory_5560 {
  strings:
    $key_5560 = { 02 12 [2] 30 30 [2] 36 05 [2] 18 05 [2] 27 19 }

  condition:
    any of them
}