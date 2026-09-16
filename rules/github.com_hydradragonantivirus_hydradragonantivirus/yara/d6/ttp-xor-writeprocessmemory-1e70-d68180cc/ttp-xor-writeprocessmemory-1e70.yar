rule TTP_XOR_WriteProcessMemory_1e70 {
  strings:
    $key_1e70 = { 49 02 [2] 7b 20 [2] 7d 15 [2] 53 15 [2] 6c 09 }

  condition:
    any of them
}