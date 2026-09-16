rule TTP_XOR_WriteProcessMemory_3900 {
  strings:
    $key_3900 = { 6e 72 [2] 5c 50 [2] 5a 65 [2] 74 65 [2] 4b 79 }

  condition:
    any of them
}