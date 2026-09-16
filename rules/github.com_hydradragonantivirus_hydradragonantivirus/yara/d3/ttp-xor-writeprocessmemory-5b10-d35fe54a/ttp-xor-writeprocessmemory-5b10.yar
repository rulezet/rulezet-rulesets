rule TTP_XOR_WriteProcessMemory_5b10 {
  strings:
    $key_5b10 = { 0c 62 [2] 3e 40 [2] 38 75 [2] 16 75 [2] 29 69 }

  condition:
    any of them
}