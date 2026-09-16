rule TTP_XOR_WriteProcessMemory_4fa6 {
  strings:
    $key_4fa6 = { 18 d4 [2] 2a f6 [2] 2c c3 [2] 02 c3 [2] 3d df }

  condition:
    any of them
}