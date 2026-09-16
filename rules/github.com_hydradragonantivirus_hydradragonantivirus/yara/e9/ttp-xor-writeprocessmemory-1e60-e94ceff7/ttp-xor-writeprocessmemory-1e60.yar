rule TTP_XOR_WriteProcessMemory_1e60 {
  strings:
    $key_1e60 = { 49 12 [2] 7b 30 [2] 7d 05 [2] 53 05 [2] 6c 19 }

  condition:
    any of them
}