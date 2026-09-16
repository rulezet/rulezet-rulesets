rule TTP_XOR_WriteProcessMemory_4fc6 {
  strings:
    $key_4fc6 = { 18 b4 [2] 2a 96 [2] 2c a3 [2] 02 a3 [2] 3d bf }

  condition:
    any of them
}