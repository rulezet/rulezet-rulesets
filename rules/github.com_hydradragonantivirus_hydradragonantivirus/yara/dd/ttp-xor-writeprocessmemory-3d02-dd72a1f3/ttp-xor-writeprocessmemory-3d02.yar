rule TTP_XOR_WriteProcessMemory_3d02 {
  strings:
    $key_3d02 = { 6a 70 [2] 58 52 [2] 5e 67 [2] 70 67 [2] 4f 7b }

  condition:
    any of them
}