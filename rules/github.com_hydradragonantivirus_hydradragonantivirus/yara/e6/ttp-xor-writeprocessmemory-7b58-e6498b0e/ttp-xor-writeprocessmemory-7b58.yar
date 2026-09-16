rule TTP_XOR_WriteProcessMemory_7b58 {
  strings:
    $key_7b58 = { 2c 2a [2] 1e 08 [2] 18 3d [2] 36 3d [2] 09 21 }

  condition:
    any of them
}