rule TTP_XOR_WriteProcessMemory_3b10 {
  strings:
    $key_3b10 = { 6c 62 [2] 5e 40 [2] 58 75 [2] 76 75 [2] 49 69 }

  condition:
    any of them
}