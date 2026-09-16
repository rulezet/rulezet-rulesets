rule TTP_XOR_WriteProcessMemory_4f25 {
  strings:
    $key_4f25 = { 18 57 [2] 2a 75 [2] 2c 40 [2] 02 40 [2] 3d 5c }

  condition:
    any of them
}