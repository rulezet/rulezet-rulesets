rule TTP_XOR_WriteProcessMemory_6ef7 {
  strings:
    $key_6ef7 = { 39 85 [2] 0b a7 [2] 0d 92 [2] 23 92 [2] 1c 8e }

  condition:
    any of them
}