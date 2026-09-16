rule TTP_XOR_WriteProcessMemory_4b10 {
  strings:
    $key_4b10 = { 1c 62 [2] 2e 40 [2] 28 75 [2] 06 75 [2] 39 69 }

  condition:
    any of them
}