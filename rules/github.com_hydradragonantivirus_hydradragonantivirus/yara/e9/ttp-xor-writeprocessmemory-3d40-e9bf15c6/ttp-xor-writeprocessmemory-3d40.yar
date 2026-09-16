rule TTP_XOR_WriteProcessMemory_3d40 {
  strings:
    $key_3d40 = { 6a 32 [2] 58 10 [2] 5e 25 [2] 70 25 [2] 4f 39 }

  condition:
    any of them
}