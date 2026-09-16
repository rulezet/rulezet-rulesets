rule TTP_XOR_WriteProcessMemory_1ea7 {
  strings:
    $key_1ea7 = { 49 d5 [2] 7b f7 [2] 7d c2 [2] 53 c2 [2] 6c de }

  condition:
    any of them
}