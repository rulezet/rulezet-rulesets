rule TTP_XOR_WriteProcessMemory_4fd5 {
  strings:
    $key_4fd5 = { 18 a7 [2] 2a 85 [2] 2c b0 [2] 02 b0 [2] 3d ac }

  condition:
    any of them
}