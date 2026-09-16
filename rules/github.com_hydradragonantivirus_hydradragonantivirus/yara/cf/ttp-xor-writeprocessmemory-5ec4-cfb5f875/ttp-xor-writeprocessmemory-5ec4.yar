rule TTP_XOR_WriteProcessMemory_5ec4 {
  strings:
    $key_5ec4 = { 09 b6 [2] 3b 94 [2] 3d a1 [2] 13 a1 [2] 2c bd }

  condition:
    any of them
}