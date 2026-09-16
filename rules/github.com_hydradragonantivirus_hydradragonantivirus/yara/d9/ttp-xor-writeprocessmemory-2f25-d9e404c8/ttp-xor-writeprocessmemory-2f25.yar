rule TTP_XOR_WriteProcessMemory_2f25 {
  strings:
    $key_2f25 = { 78 57 [2] 4a 75 [2] 4c 40 [2] 62 40 [2] 5d 5c }

  condition:
    any of them
}