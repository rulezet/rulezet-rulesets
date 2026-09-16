rule TTP_XOR_WriteProcessMemory_5eba {
  strings:
    $key_5eba = { 09 c8 [2] 3b ea [2] 3d df [2] 13 df [2] 2c c3 }

  condition:
    any of them
}