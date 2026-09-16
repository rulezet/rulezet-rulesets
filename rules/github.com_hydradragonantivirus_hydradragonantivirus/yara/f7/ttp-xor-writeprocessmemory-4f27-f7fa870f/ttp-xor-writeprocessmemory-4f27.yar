rule TTP_XOR_WriteProcessMemory_4f27 {
  strings:
    $key_4f27 = { 18 55 [2] 2a 77 [2] 2c 42 [2] 02 42 [2] 3d 5e }

  condition:
    any of them
}