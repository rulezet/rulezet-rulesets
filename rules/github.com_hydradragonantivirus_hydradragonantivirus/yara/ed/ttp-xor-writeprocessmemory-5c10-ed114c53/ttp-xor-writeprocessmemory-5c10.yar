rule TTP_XOR_WriteProcessMemory_5c10 {
  strings:
    $key_5c10 = { 0b 62 [2] 39 40 [2] 3f 75 [2] 11 75 [2] 2e 69 }

  condition:
    any of them
}