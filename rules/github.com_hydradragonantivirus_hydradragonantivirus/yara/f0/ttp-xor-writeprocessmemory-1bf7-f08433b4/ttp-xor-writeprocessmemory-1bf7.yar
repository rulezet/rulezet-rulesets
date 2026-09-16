rule TTP_XOR_WriteProcessMemory_1bf7 {
  strings:
    $key_1bf7 = { 4c 85 [2] 7e a7 [2] 78 92 [2] 56 92 [2] 69 8e }

  condition:
    any of them
}