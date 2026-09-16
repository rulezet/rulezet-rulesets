rule TTP_XOR_WriteProcessMemory_1e58 {
  strings:
    $key_1e58 = { 49 2a [2] 7b 08 [2] 7d 3d [2] 53 3d [2] 6c 21 }

  condition:
    any of them
}