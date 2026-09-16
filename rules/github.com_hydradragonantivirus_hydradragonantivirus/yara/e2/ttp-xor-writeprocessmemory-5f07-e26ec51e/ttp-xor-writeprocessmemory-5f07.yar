rule TTP_XOR_WriteProcessMemory_5f07 {
  strings:
    $key_5f07 = { 08 75 [2] 3a 57 [2] 3c 62 [2] 12 62 [2] 2d 7e }

  condition:
    any of them
}