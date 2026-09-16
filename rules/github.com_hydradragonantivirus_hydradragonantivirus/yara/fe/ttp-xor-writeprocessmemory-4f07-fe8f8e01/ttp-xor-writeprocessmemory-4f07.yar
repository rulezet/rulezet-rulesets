rule TTP_XOR_WriteProcessMemory_4f07 {
  strings:
    $key_4f07 = { 18 75 [2] 2a 57 [2] 2c 62 [2] 02 62 [2] 3d 7e }

  condition:
    any of them
}