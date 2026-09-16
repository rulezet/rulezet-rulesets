rule TTP_XOR_WriteProcessMemory_3e50 {
  strings:
    $key_3e50 = { 69 22 [2] 5b 00 [2] 5d 35 [2] 73 35 [2] 4c 29 }

  condition:
    any of them
}