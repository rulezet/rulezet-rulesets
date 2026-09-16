rule TTP_XOR_WriteProcessMemory_2c58 {
  strings:
    $key_2c58 = { 7b 2a [2] 49 08 [2] 4f 3d [2] 61 3d [2] 5e 21 }

  condition:
    any of them
}