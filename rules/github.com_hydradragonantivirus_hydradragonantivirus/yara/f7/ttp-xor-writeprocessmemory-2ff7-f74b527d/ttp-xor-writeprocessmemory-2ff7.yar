rule TTP_XOR_WriteProcessMemory_2ff7 {
  strings:
    $key_2ff7 = { 78 85 [2] 4a a7 [2] 4c 92 [2] 62 92 [2] 5d 8e }

  condition:
    any of them
}