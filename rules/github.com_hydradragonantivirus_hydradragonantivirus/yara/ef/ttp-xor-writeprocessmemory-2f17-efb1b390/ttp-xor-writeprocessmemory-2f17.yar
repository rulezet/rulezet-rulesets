rule TTP_XOR_WriteProcessMemory_2f17 {
  strings:
    $key_2f17 = { 78 65 [2] 4a 47 [2] 4c 72 [2] 62 72 [2] 5d 6e }

  condition:
    any of them
}