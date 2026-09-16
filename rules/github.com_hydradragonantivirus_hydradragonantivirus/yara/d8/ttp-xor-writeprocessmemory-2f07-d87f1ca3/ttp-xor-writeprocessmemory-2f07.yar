rule TTP_XOR_WriteProcessMemory_2f07 {
  strings:
    $key_2f07 = { 78 75 [2] 4a 57 [2] 4c 62 [2] 62 62 [2] 5d 7e }

  condition:
    any of them
}