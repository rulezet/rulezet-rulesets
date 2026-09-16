rule TTP_XOR_WriteProcessMemory_3ff7 {
  strings:
    $key_3ff7 = { 68 85 [2] 5a a7 [2] 5c 92 [2] 72 92 [2] 4d 8e }

  condition:
    any of them
}