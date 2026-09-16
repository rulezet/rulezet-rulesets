rule TTP_XOR_WriteProcessMemory_4fa5 {
  strings:
    $key_4fa5 = { 18 d7 [2] 2a f5 [2] 2c c0 [2] 02 c0 [2] 3d dc }

  condition:
    any of them
}