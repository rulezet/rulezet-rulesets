rule TTP_XOR_WriteProcessMemory_4f23 {
  strings:
    $key_4f23 = { 18 51 [2] 2a 73 [2] 2c 46 [2] 02 46 [2] 3d 5a }

  condition:
    any of them
}