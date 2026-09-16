rule TTP_XOR_WriteProcessMemory_1b10 {
  strings:
    $key_1b10 = { 4c 62 [2] 7e 40 [2] 78 75 [2] 56 75 [2] 69 69 }

  condition:
    any of them
}