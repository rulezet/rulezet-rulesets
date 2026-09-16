rule TTP_XOR_WriteProcessMemory_4fe8 {
  strings:
    $key_4fe8 = { 18 9a [2] 2a b8 [2] 2c 8d [2] 02 8d [2] 3d 91 }

  condition:
    any of them
}