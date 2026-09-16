rule TTP_XOR_WriteProcessMemory_4f18 {
  strings:
    $key_4f18 = { 18 6a [2] 2a 48 [2] 2c 7d [2] 02 7d [2] 3d 61 }

  condition:
    any of them
}