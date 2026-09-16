rule TTP_XOR_WriteProcessMemory_4ff5 {
  strings:
    $key_4ff5 = { 18 87 [2] 2a a5 [2] 2c 90 [2] 02 90 [2] 3d 8c }

  condition:
    any of them
}