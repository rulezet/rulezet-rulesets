rule TTP_XOR_WriteProcessMemory_3ea7 {
  strings:
    $key_3ea7 = { 69 d5 [2] 5b f7 [2] 5d c2 [2] 73 c2 [2] 4c de }

  condition:
    any of them
}