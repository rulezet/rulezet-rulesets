rule TTP_XOR_WriteProcessMemory_5f67 {
  strings:
    $key_5f67 = { 08 15 [2] 3a 37 [2] 3c 02 [2] 12 02 [2] 2d 1e }

  condition:
    any of them
}