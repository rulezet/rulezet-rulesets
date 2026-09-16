rule TTP_XOR_WriteProcessMemory_1060 {
  strings:
    $key_1060 = { 47 12 [2] 75 30 [2] 73 05 [2] 5d 05 [2] 62 19 }

  condition:
    any of them
}