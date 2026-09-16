rule TTP_XOR_WriteProcessMemory_1e10 {
  strings:
    $key_1e10 = { 49 62 [2] 7b 40 [2] 7d 75 [2] 53 75 [2] 6c 69 }

  condition:
    any of them
}